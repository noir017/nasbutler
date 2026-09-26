// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"

	"github.com/noir017/nasbutler/internal/approval"
)

type fakeAPI struct {
	sent    []string
	patched map[string]string
}

func (f *fakeAPI) send(_ context.Context, typ, id, card string) (string, error) {
	f.sent = append(f.sent, card)
	return fmt.Sprintf("om_%d", len(f.sent)), nil
}

func (f *fakeAPI) patch(_ context.Context, id, card string) error {
	if f.patched == nil {
		f.patched = map[string]string{}
	}
	f.patched[id] = card
	return nil
}

func newTest(decide func(context.Context, approval.Decision) error) (*Approver, *fakeAPI) {
	api := &fakeAPI{}
	a := &Approver{cfg: Config{ApproverOpenID: "ou_boss", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, api: api, decide: decide}
	return a, api
}

func click(operator string, value map[string]any) *callback.CardActionTriggerEvent {
	return &callback.CardActionTriggerEvent{Event: &callback.CardActionTriggerRequest{
		Operator: &callback.Operator{OpenID: operator},
		Action:   &callback.CallBackAction{Value: value, Tag: "button"},
	}}
}

func summary(n int) approval.Summary {
	s := approval.Summary{PlanID: "p20260926-abcdef", Digest: "d1", Kind: "plan", Title: "整理照片", Bytes: 3 << 30,
		Expires: time.Date(2026, 9, 27, 20, 0, 0, 0, time.Local)}
	for i := 0; i < n; i++ {
		s.Lines = append(s.Lines, approval.Line{Op: "move", From: fmt.Sprintf("photos/%d.jpg", i), To: fmt.Sprintf("照片/2024/%d.jpg", i)})
	}
	return s
}

func TestOnAction(t *testing.T) {
	var got []approval.Decision
	var refuse error
	a, _ := newTest(func(_ context.Context, d approval.Decision) error {
		if refuse != nil {
			return refuse
		}
		got = append(got, d)
		return nil
	})
	val := func(act string) map[string]any {
		return map[string]any{"nb": "1", "plan": "p20260926-abcdef", "digest": "d1", "act": act}
	}

	resp, _ := a.onAction(context.Background(), click("ou_boss", val("approve")))
	if len(got) != 1 || !got[0].Approve || got[0].Digest != "d1" || got[0].By != "ou_boss" || resp.Toast.Type != "success" {
		t.Fatalf("approve: decisions %+v, toast %+v", got, resp.Toast)
	}
	a.onAction(context.Background(), click("ou_boss", val("reject")))
	if len(got) != 2 || got[1].Approve {
		t.Fatalf("reject: %+v", got)
	}

	resp, _ = a.onAction(context.Background(), click("ou_intruder", val("approve")))
	if len(got) != 2 || resp.Toast.Type != "error" {
		t.Fatalf("someone else's click was accepted: %+v", got)
	}

	resp, _ = a.onAction(context.Background(), click("ou_boss", map[string]any{"plan": "x", "act": "approve"}))
	if len(got) != 2 || resp == nil || resp.Toast == nil {
		t.Fatal("a card without the nasbutler marker was treated as ours")
	}

	refuse = errors.New("the plan expired")
	resp, _ = a.onAction(context.Background(), click("ou_boss", val("approve")))
	if resp.Toast.Type != "error" || !strings.Contains(resp.Toast.Content, "expired") {
		t.Fatalf("refusal not shown to the approver: %+v", resp.Toast)
	}

	for _, ev := range []*callback.CardActionTriggerEvent{nil, {}, click("ou_boss", nil)} {
		if resp, err := a.onAction(context.Background(), ev); resp == nil || err != nil {
			t.Fatal("callbacks must always be acknowledged with a non-nil response")
		}
	}
}

func TestOnActionTest(t *testing.T) {
	a, _ := newTest(nil)
	var who string
	a.cfg.OnTest = func(id string) { who = id }
	a.onAction(context.Background(), click("ou_someone", map[string]any{"nb": "1", "act": "test"}))
	if who != "ou_someone" {
		t.Fatalf("OnTest got %q", who)
	}
}

// buttons returns the callback values of all buttons in a card.
func buttons(t *testing.T, card string) []map[string]any {
	t.Helper()
	var c map[string]any
	if err := json.Unmarshal([]byte(card), &c); err != nil {
		t.Fatal(err)
	}
	if c["schema"] != "2.0" {
		t.Fatalf("schema = %v", c["schema"])
	}
	var out []map[string]any
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if x["tag"] == "button" {
				b := x["behaviors"].([]any)[0].(map[string]any)
				out = append(out, b["value"].(map[string]any))
			}
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(c)
	return out
}

func TestCards(t *testing.T) {
	a, api := newTest(nil)
	tk, err := a.Request(context.Background(), summary(25))
	if err != nil || tk.Ref != "om_1" || tk.PlanID != "p20260926-abcdef" {
		t.Fatalf("Request = %+v, %v", tk, err)
	}
	card := api.sent[0]
	bs := buttons(t, card)
	if len(bs) != 2 || bs[0]["act"] != "approve" || bs[1]["act"] != "reject" || bs[0]["digest"] != "d1" || bs[0]["nb"] != "1" {
		t.Fatalf("buttons = %+v", bs)
	}
	if !strings.Contains(card, "20. 移动 photos/19.jpg") || strings.Contains(card, "photos/20.jpg") || !strings.Contains(card, "另外 5 项") {
		t.Error("card should list 20 operations and summarise the rest")
	}
	if !strings.Contains(card, "3.0 GiB") || !strings.Contains(card, "2026-09-27 20:00") {
		t.Error("card lacks size or expiry")
	}

	a.Update(context.Background(), tk, summary(1), approval.Outcome{State: "done", Done: 1, Total: 1})
	if patched := api.patched["om_1"]; len(buttons(t, patched)) != 0 || !strings.Contains(patched, "已完成") {
		t.Errorf("outcome card = %s", patched)
	}
}

func TestPlainTextOnly(t *testing.T) {
	s := summary(1)
	s.Title = "**bold** <at id=all></at> [x](http://evil)"
	card, _ := pendingCard(s)
	if strings.Contains(card, `"markdown"`) || strings.Contains(card, `"lark_md"`) {
		t.Fatal("agent-supplied text must only go into plain_text elements")
	}
}
