// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

// Package feishu approves plans with Feishu (Lark) interactive cards.
//
// The card is sent as a direct message from the app's bot to the approver.
// Button clicks come back over the app's long connection (WebSocket), so
// no public endpoint is needed. Only clicks by the configured approver's
// open_id count.
//
// Feishu delivers each callback to one of the app's connected clients at
// random. If another program holds a long connection for the same app,
// some clicks will go to it instead: use an app nothing else listens on,
// and check with `nasbutler feishu test`.
package feishu

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkws "github.com/larksuite/oapi-sdk-go/v3/ws"

	"github.com/noir017/nasbutler/internal/approval"
)

// Config configures the approver.
type Config struct {
	AppID, AppSecret string
	ApproverOpenID   string
	BaseURL          string // https://open.feishu.cn or https://open.larksuite.com
	Log              *slog.Logger
	// OnTest, if set, receives the open_id of whoever clicks a test card.
	OnTest func(openID string)
}

// Approver implements approval.Approver.
type Approver struct {
	cfg Config
	api messenger

	mu     sync.Mutex
	decide func(context.Context, approval.Decision) error
}

// messenger is the slice of the Feishu API the approver uses; tests swap
// in a fake.
type messenger interface {
	send(ctx context.Context, receiveIDType, receiveID, card string) (messageID string, err error)
	patch(ctx context.Context, messageID, card string) error
}

// New returns an approver. It does not connect until Run.
func New(cfg Config) *Approver {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	client := lark.NewClient(cfg.AppID, cfg.AppSecret,
		lark.WithOpenBaseUrl(cfg.BaseURL),
		lark.WithLogger(logAdapter{cfg.Log}),
		lark.WithLogLevel(larkcore.LogLevelWarn),
		lark.WithReqTimeout(15*time.Second))
	return &Approver{cfg: cfg, api: larkAPI{client}}
}

func (a *Approver) Name() string { return "feishu" }

// Run holds the long connection and turns button clicks into decisions.
func (a *Approver) Run(ctx context.Context, decide func(context.Context, approval.Decision) error) error {
	a.mu.Lock()
	a.decide = decide
	a.mu.Unlock()
	h := dispatcher.NewEventDispatcher("", "").OnP2CardActionTrigger(a.onAction)
	cli := larkws.NewClient(a.cfg.AppID, a.cfg.AppSecret,
		larkws.WithEventHandler(h),
		larkws.WithDomain(a.cfg.BaseURL),
		larkws.WithLogger(logAdapter{a.cfg.Log}),
		larkws.WithLogLevel(larkcore.LogLevelInfo))
	err := cli.Start(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Request sends the approval card to the approver.
func (a *Approver) Request(ctx context.Context, s approval.Summary) (approval.Ticket, error) {
	card, err := pendingCard(s)
	if err != nil {
		return approval.Ticket{}, err
	}
	id, err := a.api.send(ctx, "open_id", a.cfg.ApproverOpenID, card)
	return approval.Ticket{PlanID: s.PlanID, Ref: id}, err
}

// Update replaces the card with the outcome, removing the buttons.
func (a *Approver) Update(ctx context.Context, t approval.Ticket, s approval.Summary, o approval.Outcome) error {
	if t.Ref == "" {
		return nil
	}
	card, err := outcomeCard(s, o)
	if err != nil {
		return err
	}
	return a.api.patch(ctx, t.Ref, card)
}

// SendTest sends a card with one button; clicks are reported to OnTest.
// receiveIDType is "open_id" or "email".
func (a *Approver) SendTest(ctx context.Context, receiveIDType, receiveID string) error {
	card, err := testCard()
	if err != nil {
		return err
	}
	_, err = a.api.send(ctx, receiveIDType, receiveID, card)
	return err
}

func toast(kind, text string) *callback.CardActionTriggerResponse {
	// Always a non-nil response: the SDK acknowledges card callbacks only
	// when the handler returns one.
	return &callback.CardActionTriggerResponse{Toast: &callback.Toast{Type: kind, Content: text}}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func (a *Approver) onAction(ctx context.Context, ev *callback.CardActionTriggerEvent) (*callback.CardActionTriggerResponse, error) {
	if ev == nil || ev.Event == nil || ev.Event.Action == nil {
		return toast("info", "ignored"), nil
	}
	v := ev.Event.Action.Value
	if str(v, valueMarker) != "1" {
		a.cfg.Log.Warn("card callback for a card nasbutler did not send; another program may share this Feishu app")
		return toast("info", "这不是 nasbutler 的卡片"), nil
	}
	operator := ""
	if ev.Event.Operator != nil {
		operator = ev.Event.Operator.OpenID
	}
	act := str(v, "act")
	if act == "test" {
		if a.cfg.OnTest != nil {
			a.cfg.OnTest(operator)
		}
		return toast("success", "nasbutler 收到了这次点击"), nil
	}
	if operator == "" || operator != a.cfg.ApproverOpenID {
		a.cfg.Log.Warn("card click by someone other than the approver", "plan", str(v, "plan"))
		return toast("error", "你不是这个计划的审批人"), nil
	}
	if act != "approve" && act != "reject" {
		return toast("error", "未知操作"), nil
	}
	a.mu.Lock()
	decide := a.decide
	a.mu.Unlock()
	if decide == nil {
		return toast("error", "执行器还没准备好，请稍后再试"), nil
	}
	d := approval.Decision{PlanID: str(v, "plan"), Digest: str(v, "digest"), Approve: act == "approve", By: operator}
	if err := decide(ctx, d); err != nil {
		return toast("error", "没有执行："+err.Error()), nil
	}
	if d.Approve {
		return toast("success", "已批准，开始执行"), nil
	}
	return toast("info", "已拒绝"), nil
}

type larkAPI struct{ c *lark.Client }

func (l larkAPI) send(ctx context.Context, receiveIDType, receiveID, card string) (string, error) {
	resp, err := l.c.Im.Message.Create(ctx, larkim.NewCreateMessageReqBuilder().
		ReceiveIdType(receiveIDType).
		Body(larkim.NewCreateMessageReqBodyBuilder().ReceiveId(receiveID).MsgType("interactive").Content(card).Build()).
		Build())
	if err != nil {
		return "", err
	}
	if !resp.Success() {
		return "", fmt.Errorf("feishu send message: code %d: %s", resp.Code, resp.Msg)
	}
	if resp.Data == nil || resp.Data.MessageId == nil {
		return "", errors.New("feishu send message: no message id in response")
	}
	return *resp.Data.MessageId, nil
}

func (l larkAPI) patch(ctx context.Context, messageID, card string) error {
	resp, err := l.c.Im.Message.Patch(ctx, larkim.NewPatchMessageReqBuilder().
		MessageId(messageID).
		Body(larkim.NewPatchMessageReqBodyBuilder().Content(card).Build()).
		Build())
	if err != nil {
		return err
	}
	if !resp.Success() {
		return fmt.Errorf("feishu update message: code %d: %s", resp.Code, resp.Msg)
	}
	return nil
}

// logAdapter routes the SDK's logging into slog.
type logAdapter struct{ l *slog.Logger }

func (a logAdapter) Debug(_ context.Context, v ...interface{}) {
	a.l.Debug("feishu: " + fmt.Sprint(v...))
}
func (a logAdapter) Info(_ context.Context, v ...interface{}) {
	a.l.Info("feishu: " + fmt.Sprint(v...))
}
func (a logAdapter) Warn(_ context.Context, v ...interface{}) {
	a.l.Warn("feishu: " + fmt.Sprint(v...))
}
func (a logAdapter) Error(_ context.Context, v ...interface{}) {
	a.l.Error("feishu: " + fmt.Sprint(v...))
}
