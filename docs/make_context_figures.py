#!/usr/bin/env python3
"""Charts that explain context carrying, from the Copilot CLI local usage store.

Reads ~/.copilot/session-store.db read-only (table assistant_usage_events), writes four
PNG files to docs/figures/ and prints the numbers quoted in the write-up.

    python3 docs/make_context_figures.py [--db PATH] [--out DIR]

A call is one model request. Its prompt is input_tokens, which already includes the
cache-read and cache-write tokens (true on every row checked). Costs come from
token_details_json, so the split by token type is exact for every model.
"""
import argparse
import json
import sqlite3
from collections import defaultdict
from datetime import datetime
from itertools import accumulate
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

TYPES = ("cache_read", "cache_write", "input", "output")
NAMES = {
    "cache_read": "re-read from cache (carried)",
    "cache_write": "written to cache (new text)",
    "input": "uncached input",
    "output": "output (the answer)",
}
SHORT = {
    "cache_read": "cache read\n(re-read)",
    "cache_write": "cache write\n(new text)",
    "input": "uncached\ninput",
    "output": "output",
}
COLORS = {"cache_read": "#3b6ea5", "cache_write": "#e08a1e", "input": "#8c96a3", "output": "#2f9e6f"}
NAVY, GREY, RED = "#2b3a55", "#4a5260", "#c0392b"
COMPACT_DEFAULT, COMPACT_LONG = 160_000, 750_000
COLD_GAP_S = 300
EDGES = (0, 25_000, 50_000, 100_000, 200_000, 400_000, float("inf"))
BUCKETS = ("<25k", "25–50k", "50–100k", "100–200k", "200–400k", "≥400k")
KFMT = FuncFormatter(lambda v, _: f"{v / 1000:.0f}k")

plt.rcParams.update({
    "font.size": 8,
    "axes.titlesize": 8.5,
    "axes.titleweight": "bold",
    "axes.titlelocation": "left",
    "axes.spines.top": False,
    "axes.spines.right": False,
})


def load(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    sql = """SELECT session_id, agent_id, model, input_tokens, cache_read_tokens, cache_write_tokens,
                    output_tokens, total_nano_aiu, created_at, token_details_json
             FROM assistant_usage_events ORDER BY session_id, id"""
    calls = []
    for sid, agent, model, inp, rd, wr, out, nano, ts, det in con.execute(sql):
        inp, rd, wr, out = inp or 0, rd or 0, wr or 0, out or 0
        aiu, price = dict.fromkeys(TYPES, 0.0), {}
        for d in json.loads(det) if det else []:
            t = d["tokenType"]
            if t in aiu:
                per_token = d["costPerBatch"] / d["batchSize"] / 1e9
                aiu[t] += d["tokenCount"] * per_token
                price[t] = per_token * 1e6
        calls.append({
            "sid": sid, "agent": agent, "model": model, "prompt": inp, "total": (nano or 0) / 1e9,
            "tok": {"cache_read": rd, "cache_write": wr, "input": max(inp - rd - wr, 0), "output": out},
            "aiu": aiu, "price": price,
            "ts": datetime.fromisoformat(ts.replace("T", " ").replace("Z", "")) if ts else None,
        })
    return calls


def flag_cold(calls):
    """Cold = the first call after a pause of 5 min or more that finds less than half its prompt cached."""
    seqs = defaultdict(list)
    for c in calls:
        seqs[(c["sid"], c["agent"])].append(c)
    for seq in seqs.values():
        for prev, c in zip([None] + seq[:-1], seq):
            gap = (c["ts"] - prev["ts"]).total_seconds() if prev and prev["ts"] and c["ts"] else 0
            c["cold"] = gap >= COLD_GAP_S and c["tok"]["cache_read"] < 0.5 * c["prompt"]


def by_session(calls):
    sessions = defaultdict(list)
    for c in calls:
        if c["agent"] is None:
            sessions[c["sid"]].append(c)
    return sessions


def pick_anatomy(sessions, model, n=60):
    """A long single-model session whose first calls are the most cache-warm: a clean picture of the mechanism."""
    best, best_key = None, None
    for sid, seq in sessions.items():
        if len(seq) < 2 * n or {c["model"] for c in seq} != {model}:
            continue
        warm = sum(c["tok"]["cache_read"] >= 0.5 * c["prompt"] for c in seq[1:n]) / (n - 1)
        key = (warm, sum(c["total"] for c in seq))
        if best_key is None or key > best_key:
            best, best_key = sid, key
    return best or max(sessions, key=lambda s: len(sessions[s]))


def totals(calls, key):
    return {t: sum(c[key][t] for c in calls) for t in TYPES}


def bucket_stats(calls):
    n, aiu = [0] * len(BUCKETS), [0.0] * len(BUCKETS)
    for c in calls:
        i = next(j for j in range(len(BUCKETS)) if c["prompt"] < EDGES[j + 1])
        n[i] += 1
        aiu[i] += c["total"]
    return n, aiu


def beyond(calls, cap):
    """AIU spent on the prompt tokens above `cap` in each call (average prompt price per token)."""
    s = 0.0
    for c in calls:
        if c["prompt"] > cap:
            prompt_aiu = sum(c["aiu"][t] for t in ("cache_read", "cache_write", "input"))
            s += prompt_aiu * (c["prompt"] - cap) / c["prompt"]
    return s


def stacked(ax, x, series, order):
    bottom = [0.0] * len(x)
    for t in order:
        ax.bar(x, series[t], bottom=bottom, width=0.85, color=COLORS[t], label=NAMES[t], linewidth=0)
        bottom = [b + v for b, v in zip(bottom, series[t])]
    return max(bottom)


def fig_anatomy(seq, path):
    x = list(range(1, len(seq) + 1))
    fig, (a, b) = plt.subplots(2, 1, figsize=(7.2, 5.6), sharex=True, constrained_layout=True)
    peak = stacked(a, x, {t: [c["tok"][t] for c in seq] for t in TYPES}, TYPES[:3])
    a.set_ylim(0, peak * 1.5)
    a.yaxis.set_major_formatter(KFMT)
    a.set_title("a) What is sent to the model at every call (tokens)")
    a.legend(loc="upper left", ncol=3, frameon=False, fontsize=7)
    a.text(0.01, 0.84, "Every call re-sends the whole conversation so far. The blue part grows\n"
           "with each step; the orange part (the new text) stays small.",
           transform=a.transAxes, va="top", fontsize=7.5, color=NAVY)
    peak = stacked(b, x, {t: [c["aiu"][t] for c in seq] for t in TYPES}, TYPES)
    b.set_ylim(0, peak * 1.4)
    b.set_title("b) What each call costs (AIU)")
    b.legend(loc="upper left", ncol=2, frameon=False, fontsize=7)
    b.set_xlabel("Call number in the session (main agent)")
    fig.savefig(path, dpi=200)
    plt.close(fig)


def fig_growth(seq, path):
    x = list(range(1, len(seq) + 1))
    prompt = [c["prompt"] for c in seq]
    fig, (a, b) = plt.subplots(2, 1, figsize=(7.2, 5.2), sharex=True, constrained_layout=True,
                               gridspec_kw={"height_ratios": [1.2, 1]})
    a.plot(x, prompt, color=NAVY, lw=0.7, label="prompt size at each call")
    cold = [(i, c["prompt"]) for i, c in enumerate(seq, 1) if c["cold"]]
    if cold:
        a.scatter(*zip(*cold), s=9, color=RED, zorder=3, label="call after a pause of 5 min or more (cache expired)")
    top = max(max(prompt), COMPACT_DEFAULT) * 1.12
    # The 750k label goes bottom-left, where the prompt curve is still low; the 160k one goes right.
    for cap, text, side in ((COMPACT_DEFAULT, "default window: history summarised at about 160k", "right"),
                            (COMPACT_LONG, "long_context window: summarised at about 750k", "left")):
        if cap < top:
            a.axhline(cap, color="#7a828f", ls="--", lw=0.8)
            if side == "right":
                a.text(len(seq), cap, text, ha="right", va="bottom", fontsize=7, color=GREY)
            else:
                a.text(1, cap, text, ha="left", va="top", fontsize=7, color=GREY)
    a.set_ylim(0, top)
    a.yaxis.set_major_formatter(KFMT)
    a.set_title("a) Size of the prompt re-sent at every call (one real long session)")
    a.legend(loc="upper left", frameon=False, fontsize=7)
    read = list(accumulate(c["aiu"]["cache_read"] for c in seq))
    write = list(accumulate(c["aiu"]["cache_write"] for c in seq))
    rest = list(accumulate(c["aiu"]["input"] + c["aiu"]["output"] for c in seq))
    b.stackplot(x, read, write, rest, linewidth=0,
                colors=[COLORS["cache_read"], COLORS["cache_write"], COLORS["output"]],
                labels=[NAMES["cache_read"], NAMES["cache_write"], "output + uncached input"])
    b.set_title("b) Cumulative cost of the same session (AIU)")
    b.set_xlabel("Call number in the session (main agent)")
    b.legend(loc="upper left", frameon=False, fontsize=7)
    total = sum(c["total"] for c in seq)
    b.set_ylim(0, total * 1.14)
    b.text(len(seq), total * 1.02, f"{total:,.0f} AIU in {len(seq):,} calls",
           ha="right", va="bottom", fontsize=8, color=NAVY, fontweight="bold")
    fig.savefig(path, dpi=200)
    plt.close(fig)


def fig_price_split(price, model, tok_tot, aiu_tot, cold_pct, path):
    fig, (ax_a, ax_b, ax_c) = plt.subplots(1, 3, figsize=(7.2, 3.2), constrained_layout=True,
                                           gridspec_kw={"width_ratios": [1.3, 1, 1]})
    order = ("cache_read", "input", "cache_write", "output")
    ax_a.barh(range(len(order)), [price[t] for t in order], color=[COLORS[t] for t in order], height=0.62)
    ax_a.set_yticks(range(len(order)), [SHORT[t] for t in order])
    ax_a.invert_yaxis()
    ax_a.set_xlim(0, 1250)
    for i, t in enumerate(order):
        ax_a.text(price[t] + 20, i, f"{price[t]:g}", va="center", fontsize=7.5)
    ax_a.set_title("a) Price per 1M tokens (AIU)")
    ax_a.set_xlabel(model, fontsize=7, color=GREY)

    bottoms = [0.0, 0.0]
    for t in TYPES:
        for i, tot in enumerate((tok_tot, aiu_tot)):
            v = tot[t] / sum(tot.values()) * 100
            ax_b.bar(i, v, bottom=bottoms[i], width=0.62, color=COLORS[t], label=NAMES[t] if i == 0 else None)
            if v >= 6:
                ax_b.text(i, bottoms[i] + v / 2, f"{v:.0f}%", ha="center", va="center",
                          color="white", fontsize=7.5, fontweight="bold")
            elif v >= 2.5:
                # Thin slice: the label goes beside the bar, in the slice colour.
                ax_b.text(i + 0.34, bottoms[i] + v / 2, f"{v:.0f}%", ha="left", va="center",
                          color=COLORS[t], fontsize=7.5, fontweight="bold")
            bottoms[i] += v
    ax_b.set_xticks([0, 1], ["share of\ntokens", "share of\nAIU"])
    ax_b.set_ylim(0, 100)
    ax_b.set_title("b) Tokens vs. money")

    warm, cold = 100_000 * price["cache_read"] / 1e6, 100_000 * price["cache_write"] / 1e6
    ax_c.bar([0, 1], [warm, cold], width=0.6, color=[COLORS["cache_read"], COLORS["cache_write"]])
    ax_c.set_xticks([0, 1], ["cache warm\n(re-read)", "cache expired\n(re-written)"])
    ax_c.text(0, warm + 0.5, f"{warm:g} AIU", ha="center", fontsize=8)
    ax_c.text(1, cold + 0.5, f"{cold:g} AIU", ha="center", fontsize=8)
    ax_c.set_ylim(0, cold * 1.2)
    ax_c.set_title("c) 100k tokens re-sent")
    ax_c.text(0, cold * 0.58, f"{cold / warm:.1f}×\ndearer", ha="center", va="center",
              fontsize=11, color=RED, fontweight="bold")
    ax_c.set_xlabel(f"The cache lives 5 min.\nMeasured: {cold_pct[0]:.1f}% of calls,\n"
                    f"{cold_pct[1]:.0f}% of AIU follow a\npause with a cold cache", fontsize=7, color=RED)
    fig.legend(*ax_b.get_legend_handles_labels(), loc="outside lower center", ncol=4, frameon=False, fontsize=7)
    fig.savefig(path, dpi=200)
    plt.close(fig)


def fig_buckets(n, aiu, path):
    pc = [v / sum(n) * 100 for v in n]
    pa = [v / sum(aiu) * 100 for v in aiu]
    avg = [a / m if m else 0 for a, m in zip(aiu, n)]
    x = list(range(len(BUCKETS)))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7.2, 3.3), constrained_layout=True)
    ax.bar([i - w / 2 for i in x], pc, w, color="#8c96a3", label="share of all calls")
    ax.bar([i + w / 2 for i in x], pa, w, color=NAVY, label="share of all AIU")
    for i in x:
        ax.text(i - w / 2, pc[i] + 0.6, f"{pc[i]:.0f}%", ha="center", fontsize=7.5)
        ax.text(i + w / 2, pa[i] + 0.6, f"{pa[i]:.0f}%", ha="center", fontsize=7.5, color=NAVY, fontweight="bold")
    ax.set_xticks(x, [f"{BUCKETS[i]}\n{avg[i]:.1f} AIU/call" for i in x])
    ax.set_xlabel("Prompt size of the call (tokens), and average cost of one call")
    ax.set_ylim(0, max(pc + pa) * 1.45)
    ax.legend(loc="upper left", ncol=2, frameon=False)
    ax.text(0.01, 0.90, f"Prompts of 100k tokens or more: {sum(pc[3:]):.0f}% of calls but {sum(pa[3:]):.0f}% of AIU",
            transform=ax.transAxes, va="top", fontsize=8, color=NAVY)
    ax.set_title("Few calls with a big prompt carry most of the bill")
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="Context-carrying charts from the Copilot CLI usage store.")
    ap.add_argument("--db", default=str(Path.home() / ".copilot" / "session-store.db"))
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "figures"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    calls = load(args.db)
    flag_cold(calls)
    tot = sum(c["total"] for c in calls)
    tok_tot, aiu_tot = totals(calls, "tok"), totals(calls, "aiu")
    per_model = defaultdict(float)
    for c in calls:
        per_model[c["model"]] += c["total"]
    top_model = max(per_model, key=per_model.get)
    price = next(c["price"] for c in calls if c["model"] == top_model and len(c["price"]) == len(TYPES))
    n, aiu = bucket_stats(calls)
    cold = [c for c in calls if c["cold"]]
    cold_pct = (len(cold) / len(calls) * 100, sum(c["total"] for c in cold) / tot * 100)
    sessions = by_session(calls)
    anat = sessions[pick_anatomy(sessions, top_model)][:60]
    big = max(sessions.values(), key=lambda s: sum(c["total"] for c in s))

    fig_anatomy(anat, out / "ctx-1-anatomy.png")
    fig_growth(big, out / "ctx-2-growth.png")
    fig_price_split(price, top_model, tok_tot, aiu_tot, cold_pct, out / "ctx-3-price-split.png")
    fig_buckets(n, aiu, out / "ctx-4-size-buckets.png")

    stamps = [c["ts"] for c in calls if c["ts"]]
    print(f"calls {len(calls):,} (main {sum(c['agent'] is None for c in calls):,}), "
          f"sessions {len({c['sid'] for c in calls})}, AIU {tot:,.0f}, {min(stamps):%Y-%m-%d} to {max(stamps):%Y-%m-%d}")
    print(f"rows without cost details {sum(not c['price'] for c in calls)}; "
          f"four token types cover {sum(aiu_tot.values()) / tot * 100:.2f}% of AIU; top model {top_model} "
          f"({per_model[top_model] / tot * 100:.0f}% of AIU); prices {price}")
    print("AIU share by type  :", {t: round(aiu_tot[t] / sum(aiu_tot.values()) * 100, 1) for t in TYPES})
    print("token share by type:", {t: round(tok_tot[t] / sum(tok_tot.values()) * 100, 2) for t in TYPES})
    print(f"mean prompt {sum(c['prompt'] for c in calls) / len(calls):,.0f} tokens; AIU-weighted mean prompt "
          f"{sum(c['prompt'] * c['total'] for c in calls) / tot:,.0f}")
    for i, label in enumerate(BUCKETS):
        print(f"  {label:>8}: calls {n[i] / sum(n) * 100:5.1f}%  AIU {aiu[i] / sum(aiu) * 100:5.1f}%  "
              f"avg {aiu[i] / max(n[i], 1):6.2f} AIU/call")
    print(f"prompt >=100k: calls {sum(n[3:]) / sum(n) * 100:.1f}% AIU {sum(aiu[3:]) / sum(aiu) * 100:.1f}%; "
          f">=400k: calls {n[5] / sum(n) * 100:.1f}% AIU {aiu[5] / sum(aiu) * 100:.1f}%")
    print(f"AIU on prompt tokens above 160k: {beyond(calls, COMPACT_DEFAULT) / tot * 100:.1f}% of all AIU; "
          f"above 200k: {beyond(calls, 200_000) / tot * 100:.1f}%")
    print(f"cold calls {len(cold):,} = {cold_pct[0]:.1f}% of calls, {cold_pct[1]:.1f}% of AIU")
    k = [i for i in (0, 1, 9, 29, 59) if i < len(anat)]
    print(f"anatomy session {anat[0]['sid'][:8]} {anat[0]['model']}: prompt at calls "
          f"{[(i + 1, anat[i]['prompt']) for i in k]}; AIU at those calls {[round(anat[i]['total'], 1) for i in k]}; "
          f"window AIU split { {t: round(sum(c['aiu'][t] for c in anat) / sum(c['total'] for c in anat) * 100) for t in TYPES} }; "
          f"window total {sum(c['total'] for c in anat):.0f} AIU")
    hi = [c for c in big if c["prompt"] >= 400_000]
    bc = [c for c in big if c["cold"]]
    bt = sum(c["total"] for c in big)
    print(f"growth session {big[0]['sid'][:8]}: {len(big):,} calls, {bt:,.0f} AIU ({bt / tot * 100:.1f}% of all), "
          f"models {sorted({c['model'] for c in big})}, max prompt {max(c['prompt'] for c in big):,}; "
          f"calls >=400k {len(hi)} = {sum(c['total'] for c in hi) / bt * 100:.0f}% of its AIU; "
          f"cold calls {len(bc)} = {sum(c['total'] for c in bc) / bt * 100:.0f}% of its AIU")
    cw = sum(c["aiu"]["cache_write"] for c in cold)
    print(f"carrying = cache read + cache write = {(aiu_tot['cache_read'] + aiu_tot['cache_write']) / tot * 100:.1f}% of AIU; "
          f"cache writes on cold calls = {cw / tot * 100:.1f}% of all AIU = {cw / aiu_tot['cache_write'] * 100:.0f}% of all cache-write AIU")
    for lo, hi, label in ((100_000, 200_000, "100-200k"), (400_000, float("inf"), ">=400k")):
        warm_c = [c["total"] for c in calls if lo <= c["prompt"] < hi and not c["cold"]]
        cold_c = [c["total"] for c in cold if lo <= c["prompt"] < hi]
        print(f"warm vs cold call at {label}: {sum(warm_c) / len(warm_c):.1f} vs {sum(cold_c) / len(cold_c):.1f} AIU "
              f"({sum(cold_c) / len(cold_c) / (sum(warm_c) / len(warm_c)):.1f}x), {len(cold_c)} cold calls")
    for label, grp in (("main agent", [c for c in calls if c["agent"] is None]),
                       ("sub-agents", [c for c in calls if c["agent"] is not None])):
        print(f"{label}: {len(grp):,} calls ({len(grp) / len(calls) * 100:.0f}%), "
              f"{sum(c['total'] for c in grp) / tot * 100:.1f}% of AIU, mean prompt {sum(c['prompt'] for c in grp) / len(grp):,.0f}")
    cum = list(accumulate(c["total"] for c in big))
    drops = [(i + 1, big[i - 1]["prompt"], big[i]["prompt"]) for i in range(1, len(big))
             if big[i]["prompt"] < 0.85 * big[i - 1]["prompt"]]
    print(f"growth session: first prompt {big[0]['prompt']:,}; first half of its calls = {cum[len(big) // 2 - 1] / bt * 100:.0f}% "
          f"of its AIU, last third = {(1 - cum[len(big) * 2 // 3 - 1] / bt) * 100:.0f}%; median call, first 50 vs last 50: "
          f"{median(c['total'] for c in big[:50]):.1f} vs {median(c['total'] for c in big[-50:]):.1f} AIU; "
          f"mean cold call {sum(c['total'] for c in bc) / max(len(bc), 1):.0f} AIU; prompt drops {drops}")
    print("wrote", ", ".join(sorted(p.name for p in out.glob("ctx-*.png"))), "in", out)


if __name__ == "__main__":
    main()
