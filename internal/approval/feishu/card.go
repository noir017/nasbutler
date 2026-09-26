// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package feishu

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/noir017/nasbutler/internal/approval"
)

// valueMarker tags button values so callbacks from other cards on a shared
// app are recognised as not ours.
const valueMarker = "nb"

// maxLines is how many operations a card lists; the rest are summarised.
const maxLines = 20

// Cards use the 2.0 schema. All user- or agent-supplied text (titles,
// paths) goes into plain_text elements so that nothing in a file name can
// inject markdown, links or @mentions.
func plain(s string) map[string]any { return map[string]any{"tag": "plain_text", "content": s} }

func div(s string) map[string]any { return map[string]any{"tag": "div", "text": plain(s)} }

func button(text, kind string, value map[string]any) map[string]any {
	value[valueMarker] = "1"
	return map[string]any{
		"tag":      "column",
		"width":    "auto",
		"elements": []any{map[string]any{"tag": "button", "text": plain(text), "type": kind, "behaviors": []any{map[string]any{"type": "callback", "value": value}}}},
	}
}

func card(title, subtitle, template string, elements []any) (string, error) {
	b, err := json.Marshal(map[string]any{
		"schema": "2.0",
		"config": map[string]any{"update_multi": true},
		"header": map[string]any{"title": plain(title), "subtitle": plain(subtitle), "template": template},
		"body":   map[string]any{"elements": elements},
	})
	return string(b), err
}

var opLabel = map[string]string{"move": "移动", "quarantine": "隔离", "restore": "还原"}

// describe renders the summary lines shared by pending and outcome cards.
func describe(s approval.Summary) []any {
	counts := map[string]int{}
	for _, l := range s.Lines {
		counts[l.Op]++
	}
	var parts []string
	for _, op := range []string{"move", "quarantine", "restore"} {
		if counts[op] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", opLabel[op], counts[op]))
		}
	}
	head := fmt.Sprintf("计划：%s\n操作：共 %d 项（%s），合计 %s", s.Title, len(s.Lines), strings.Join(parts, "，"), human(s.Bytes))
	if s.Kind == "undo" {
		head = fmt.Sprintf("撤销计划 %s\n操作：共 %d 项，合计 %s", s.Target, len(s.Lines), human(s.Bytes))
	}
	var lines []string
	for i, l := range s.Lines {
		if i == maxLines {
			lines = append(lines, fmt.Sprintf("…… 另外 %d 项，在服务器上运行 nasbutler plan show %s 查看全部", len(s.Lines)-maxLines, s.PlanID))
			break
		}
		lines = append(lines, fmt.Sprintf("%d. %s %s → %s", i+1, opLabel[l.Op], shorten(l.From), shorten(l.To)))
	}
	return []any{div(head), map[string]any{"tag": "hr"}, div(strings.Join(lines, "\n"))}
}

func pendingCard(s approval.Summary) (string, error) {
	elements := describe(s)
	elements = append(elements,
		div("有效期至 "+s.Expires.Format("2006-01-02 15:04")+"。批准后按顺序执行，不会覆盖已有文件，全部可撤销。"),
		map[string]any{"tag": "column_set", "flex_mode": "none", "columns": []any{
			button("批准执行", "primary_filled", map[string]any{"plan": s.PlanID, "digest": s.Digest, "act": "approve"}),
			button("拒绝", "danger", map[string]any{"plan": s.PlanID, "digest": s.Digest, "act": "reject"}),
		}})
	title := "nasbutler 待审批"
	if s.Kind == "undo" {
		title = "nasbutler 待审批：撤销"
	}
	return card(title, s.PlanID, "orange", elements)
}

var outcomeStyle = map[string]struct{ title, template string }{
	"approved":  {"已批准，等待执行", "blue"},
	"executing": {"执行中", "blue"},
	"done":      {"已完成", "green"},
	"failed":    {"执行失败", "red"},
	"rejected":  {"已拒绝", "grey"},
	"expired":   {"已过期", "grey"},
}

func outcomeCard(s approval.Summary, o approval.Outcome) (string, error) {
	style, ok := outcomeStyle[o.State]
	if !ok {
		style = outcomeStyle["failed"]
	}
	elements := describe(s)
	result := fmt.Sprintf("结果：成功 %d，失败 %d，共 %d", o.Done, o.Failed, o.Total)
	if o.Note != "" {
		result += "\n" + o.Note
	}
	elements = append(elements, div(result))
	return card("nasbutler "+style.title, s.PlanID, style.template, elements)
}

func testCard() (string, error) {
	return card("nasbutler 连接测试", "feishu test", "blue", []any{
		div("点下面的按钮。如果终端里打印出你的 open_id，说明回调能到达 nasbutler。多点几次：每次都能收到才可靠。"),
		map[string]any{"tag": "column_set", "flex_mode": "none", "columns": []any{
			button("点我测试", "primary_filled", map[string]any{"act": "test"}),
		}},
	})
}

// shorten keeps long paths readable by cutting out the middle.
func shorten(s string) string {
	const max = 120
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max/2-1]) + "…" + string(r[len(r)-max/2:])
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	d, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		d *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(d), "KMGTPE"[exp])
}
