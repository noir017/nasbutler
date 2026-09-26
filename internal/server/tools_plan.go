// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package server

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/noir017/nasbutler/internal/catalog"
	"github.com/noir017/nasbutler/internal/plan"
)

// OpView is one planned operation as agents see it: redacted paths only.
type OpView struct {
	Index int    `json:"index"`
	Op    string `json:"op"`
	File  int64  `json:"file"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// PlanView is a plan as agents see it.
type PlanView struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Target  string         `json:"target,omitempty"`
	Title   string         `json:"title"`
	State   plan.State     `json:"state"`
	Created string         `json:"created"`
	OpCount int            `json:"op_count"`
	Ops     []OpView       `json:"ops,omitempty"`
	Issues  []plan.OpError `json:"issues,omitempty"`
	Status  *plan.Status   `json:"status,omitempty"`
}

type PlanIDIn struct {
	PlanID string `json:"plan_id" jsonschema:"plan id from plan_create or plan_list"`
}

type PlanCreateIn struct {
	Title string `json:"title" jsonschema:"one line saying what the plan does; the approver sees it"`
}

type PlanAddIn struct {
	PlanID string    `json:"plan_id" jsonschema:"a draft plan"`
	Ops    []plan.Op `json:"ops" jsonschema:"operations to append, in execution order"`
}

type PlanAddOut struct {
	PlanID   string         `json:"plan_id"`
	Accepted int            `json:"accepted"`
	Rejected []plan.OpError `json:"rejected,omitempty" jsonschema:"index is the position in this request's ops"`
	OpCount  int            `json:"op_count"`
}

type PlanListOut struct {
	Plans []PlanView `json:"plans"`
}

type PlanSubmitOut struct {
	PlanID string `json:"plan_id"`
	State  string `json:"state"`
	Next   string `json:"next"`
}

func mutating(title string) *mcp.ToolAnnotations {
	no := false
	return &mcp.ToolAnnotations{Title: title, DestructiveHint: &no, OpenWorldHint: &no}
}

func (s *Server) registerPlans(ms *mcp.Server) {
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_create", Annotations: mutating("Create a plan"),
		Description: "Start a draft plan to reorganise files. Nothing changes until the plan is submitted and a human approves it."}, s.planCreate)
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_add", Annotations: mutating("Add operations"),
		Description: "Append operations to a draft plan. Ops are {op:\"move\", file, to_dir, name} or {op:\"quarantine\", file}. There is no delete: quarantine moves a file aside and a human empties the quarantine later. Each op is validated now; rejected ones are reported and not added."}, s.planAdd)
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_show", Annotations: readOnly("Show a plan"),
		Description: "A plan's operations (redacted paths), any current validation issues, and its execution status."}, s.planShow)
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_discard", Annotations: mutating("Discard a draft"),
		Description: "Delete a draft plan. Submitted plans cannot be discarded."}, s.planDiscard)
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_submit", Annotations: mutating("Submit for approval"),
		Description: "Submit a draft plan. The executor validates it again and asks a human to approve it; nothing happens without that approval. Poll plan_status afterwards."}, s.planSubmit)
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_status", Annotations: readOnly("Plan status"),
		Description: "State of a plan: draft, submitted, pending_approval, approved, executing, done, failed, rejected or expired, with per-operation errors."}, s.planStatus)
	mcp.AddTool(ms, &mcp.Tool{Name: "plan_list", Annotations: readOnly("List plans"),
		Description: "Recent plans with their states."}, s.planList)
	mcp.AddTool(ms, &mcp.Tool{Name: "undo_request", Annotations: mutating("Request an undo"),
		Description: "Ask to reverse an executed plan (done or failed). The undo is a new plan that needs its own human approval."}, s.undoRequest)
}

func (s *Server) loadPlan(id string) (*plan.Plan, error) {
	p, err := s.o.Plans.Load(id)
	if errors.Is(err, plan.ErrNotFound) {
		return nil, errors.New("no such plan")
	}
	if err != nil {
		return nil, errors.New("invalid plan id")
	}
	return p, nil
}

func (s *Server) view(p *plan.Plan, detail bool) PlanView {
	v := PlanView{ID: p.ID, Kind: p.Kind, Target: p.Target, Title: p.Title, State: p.State,
		Created: p.Created.Format(time.RFC3339), OpCount: len(p.Ops)}
	if st, err := s.o.Plans.LoadStatus(p.ID); err == nil {
		v.Status, v.State = st, st.State
	}
	if !detail {
		return v
	}
	for i, op := range p.Ops {
		ov := OpView{Index: i, Op: op.Op, File: op.File, From: "[unknown file]"}
		name := ""
		if f, err := s.o.DB.Get(op.File); err == nil {
			ov.From, name = f.RPath, f.RName
		}
		switch op.Op {
		case plan.OpQuarantine:
			ov.To = plan.QuarantineLabel
		default:
			if op.Name != "" {
				name = op.Name
			}
			ov.To = path.Join(catalog.CleanDir(op.ToDir), name)
		}
		v.Ops = append(v.Ops, ov)
	}
	if p.State == plan.Draft && p.Kind == plan.KindPlan {
		_, v.Issues = s.o.Validator.Resolve(p.ID, p.Ops)
	}
	return v
}

func (s *Server) planCreate(ctx context.Context, _ *mcp.CallToolRequest, in PlanCreateIn) (*mcp.CallToolResult, PlanView, error) {
	if in.Title == "" || len(in.Title) > 200 {
		return nil, PlanView{}, errors.New("title must be 1-200 bytes")
	}
	p, err := s.o.Plans.Create(plan.KindPlan, in.Title, "", plan.Draft)
	if err != nil {
		return nil, PlanView{}, errors.New("could not create the plan")
	}
	return nil, s.view(p, false), nil
}

func (s *Server) planAdd(ctx context.Context, _ *mcp.CallToolRequest, in PlanAddIn) (*mcp.CallToolResult, PlanAddOut, error) {
	p, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, PlanAddOut{}, err
	}
	if p.State != plan.Draft || p.Kind != plan.KindPlan {
		return nil, PlanAddOut{}, errors.New("only draft plans can be changed")
	}
	if len(p.Ops)+len(in.Ops) > s.o.MaxOps {
		return nil, PlanAddOut{}, fmt.Errorf("a plan holds at most %d operations; split the work into several plans", s.o.MaxOps)
	}
	base := len(p.Ops)
	_, errs := s.o.Validator.Resolve(p.ID, append(append([]plan.Op{}, p.Ops...), in.Ops...))
	bad := map[int]bool{}
	out := PlanAddOut{PlanID: p.ID}
	for _, e := range errs {
		if e.Index >= base {
			bad[e.Index-base] = true
			out.Rejected = append(out.Rejected, plan.OpError{Index: e.Index - base, Error: e.Error})
		}
	}
	for i, op := range in.Ops {
		if !bad[i] {
			p.Ops = append(p.Ops, op)
			out.Accepted++
		}
	}
	if err := s.o.Plans.Save(p); err != nil {
		return nil, PlanAddOut{}, errors.New("could not save the plan")
	}
	out.OpCount = len(p.Ops)
	return nil, out, nil
}

func (s *Server) planShow(ctx context.Context, _ *mcp.CallToolRequest, in PlanIDIn) (*mcp.CallToolResult, PlanView, error) {
	p, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, PlanView{}, err
	}
	return nil, s.view(p, true), nil
}

func (s *Server) planDiscard(ctx context.Context, _ *mcp.CallToolRequest, in PlanIDIn) (*mcp.CallToolResult, PlanView, error) {
	p, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, PlanView{}, err
	}
	if p.State != plan.Draft {
		return nil, PlanView{}, errors.New("only drafts can be discarded")
	}
	if err := s.o.Plans.Delete(p.ID); err != nil {
		return nil, PlanView{}, errors.New("could not discard the plan")
	}
	v := s.view(p, false)
	v.State = "discarded"
	return nil, v, nil
}

func (s *Server) planSubmit(ctx context.Context, _ *mcp.CallToolRequest, in PlanIDIn) (*mcp.CallToolResult, PlanSubmitOut, error) {
	p, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, PlanSubmitOut{}, err
	}
	if p.State != plan.Draft || p.Kind != plan.KindPlan {
		return nil, PlanSubmitOut{}, errors.New("only draft plans can be submitted")
	}
	if len(p.Ops) == 0 {
		return nil, PlanSubmitOut{}, errors.New("the plan has no operations")
	}
	if _, errs := s.o.Validator.Resolve(p.ID, p.Ops); len(errs) > 0 {
		return nil, PlanSubmitOut{}, fmt.Errorf("%d operation(s) no longer validate; see plan_show", len(errs))
	}
	p.State = plan.Submitted
	if err := s.o.Plans.Save(p); err != nil {
		return nil, PlanSubmitOut{}, errors.New("could not save the plan")
	}
	return nil, PlanSubmitOut{PlanID: p.ID, State: string(p.State),
		Next: "The executor will validate the plan and ask a human to approve it. Poll plan_status; do not assume approval."}, nil
}

func (s *Server) planStatus(ctx context.Context, _ *mcp.CallToolRequest, in PlanIDIn) (*mcp.CallToolResult, PlanView, error) {
	p, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, PlanView{}, err
	}
	return nil, s.view(p, false), nil
}

func (s *Server) planList(ctx context.Context, _ *mcp.CallToolRequest, _ StatusIn) (*mcp.CallToolResult, PlanListOut, error) {
	plans, err := s.o.Plans.List()
	if err != nil {
		return nil, PlanListOut{}, errors.New("could not list plans")
	}
	out := PlanListOut{Plans: []PlanView{}}
	for i, p := range plans {
		if i == 50 {
			break
		}
		out.Plans = append(out.Plans, s.view(p, false))
	}
	return nil, out, nil
}

func (s *Server) undoRequest(ctx context.Context, _ *mcp.CallToolRequest, in PlanIDIn) (*mcp.CallToolResult, PlanView, error) {
	t, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, PlanView{}, err
	}
	st, err := s.o.Plans.LoadStatus(t.ID)
	if err != nil || (st.State != plan.Done && st.State != plan.Failed) || t.Kind != plan.KindPlan {
		return nil, PlanView{}, errors.New("only executed plans (done or failed) can be undone")
	}
	p, err := s.o.Plans.Create(plan.KindUndo, "undo: "+t.Title, t.ID, plan.Submitted)
	if err != nil {
		return nil, PlanView{}, errors.New("could not create the undo request")
	}
	return nil, s.view(p, false), nil
}
