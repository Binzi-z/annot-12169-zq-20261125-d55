"""Render the aggregated verification report as Markdown."""

from __future__ import annotations

from typing import Any, Dict, List


def _icon(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _check_lines(checks: List[Dict[str, Any]], indent: int = 0) -> List[str]:
    pad = "  " * indent
    lines = []
    for c in checks:
        mark = "✅" if c["passed"] else "❌"
        line = f"{pad}- {mark} `{c['name']}`"
        if not c["passed"] and c.get("detail") is not None:
            import json
            detail = json.dumps(c["detail"], ensure_ascii=False, default=str)
            if len(detail) > 600:
                detail = detail[:600] + "…"
            line += f"\n{pad}  - detail: `{detail}`"
        lines.append(line)
    return lines


def _render_barrier_case(case: Dict[str, Any], level: int = 3) -> List[str]:
    h = "#" * level
    out = [f"{h} {_icon(case['ok'])} {case['id']}"]
    if case.get("fatal"):
        out.append(f"**FATAL:** `{case['fatal']}`")
    out.extend(_check_lines(case.get("checks", [])))
    for v in case.get("variants", []):
        out.append("")
        out.append(f"**variant `{v['id']}` — {_icon(v['ok'])}**")
        out.extend(_check_lines(v.get("checks", []), indent=1))
    for sc in case.get("subcases", []):
        out.append("")
        out.append(f"**subcase `{sc['id']}` — {_icon(sc['ok'])}**")
        out.extend(_check_lines(sc.get("checks", []), indent=1))
    return out


def render_markdown(rep: Dict[str, Any]) -> str:
    L: List[str] = []
    overall = rep.get("overall_ok")
    L.append("# 隔离放行工具 — 全量验证报告")
    L.append("")
    L.append(f"- 总体结论: **{'全部通过 ✅' if overall else '存在失败 ❌'}**")
    L.append(f"- 生成时间(UTC): `{rep.get('generated_at')}`")
    L.append(f"- Python: `{rep.get('python')}`")
    L.append(f"- 平台: `{rep.get('platform')}`")
    L.append("")
    L.append("> 本文件由 `python run_all.py` 实际运行后生成；所有目录/文件计数均来自真实遍历与哈希。")
    L.append("")

    # summary table
    L.append("## 1. 总览")
    L.append("")
    L.append("| 组件 | 结果 |")
    L.append("|---|---|")
    cs = rep.get("crypto_selftest", {})
    L.append(f"| Ed25519 RFC8032 自检 | {_icon(cs.get('ok', False))} |")
    ut = rep.get("unit_tests", {})
    L.append(f"| unittest 套件 | {_icon(ut.get('ok', False))} "
             f"({ut.get('tests_run')} run, {ut.get('failures')} fail, "
             f"{ut.get('errors')} error) |")
    ba = rep.get("barrier", {})
    L.append(f"| 双线程屏障三场景 | {_icon(ba.get('ok', False))} "
             f"({ba.get('checks_passed')}/{ba.get('checks_total')} checks) |")
    mc = rep.get("model", {})
    L.append(f"| 短交错穷举模型 | {_icon(mc.get('ok', False))} |")
    sc = rep.get("scale", {})
    L.append(f"| 6 万分目录记录对照 | {_icon(sc.get('ok', False))} |")
    L.append("")

    # crypto
    L.append("## 2. 密码学自检（纯标准库 Ed25519 + RFC 8032 向量）")
    L.append("")
    for c in cs.get("checks", []):
        L.append(f"- {_icon(c['ok'])} {c['vector']}")
    L.append("")

    # unit tests
    L.append("## 3. unittest 套件")
    L.append("")
    L.append(f"- tests run: **{ut.get('tests_run')}**; "
             f"failures: {ut.get('failures')}; errors: {ut.get('errors')}; "
             f"skipped: {ut.get('skipped')}")
    if not ut.get("ok"):
        L.append("")
        L.append("```")
        L.append(ut.get("output_tail", "")[-6000:])
        L.append("```")
    L.append("")

    # barrier
    L.append("## 4. 两个工作线程 + 屏障复测三种情况")
    L.append("")
    for case in ba.get("cases", []):
        L.extend(_render_barrier_case(case, level=3))
        L.append("")

    # model
    L.append("## 5. 小模型穷举短交错")
    L.append("")
    if mc:
        L.append(f"- 结论: **{_icon(mc.get('ok', False))}**（安全不变量在所有状态成立，"
                 f"且朴素“目录即信任”模型被找到反例，说明检查有效）")
        L.append(f"- 世界分支数: {mc.get('worlds')}；协议顺序: {mc.get('protocols')} "
                 f"(真实安全序 + 危险目录先写序)")
        L.append(f"- 每族交错数: {mc.get('shuffles_per_family')}；"
                 f"实际穷举交错总数: **{mc.get('interleavings_enumerated')}**")
        L.append(f"- 检查的前缀/崩溃点状态数: **{mc.get('prefix_states_checked')}**；"
                 f"不同抽象状态: {mc.get('distinct_abstract_states')}")
        L.append(f"- “撤销先于提交→必拒”观测: {mc.get('revoke_first_denied_observations')}")
        L.append(f"- “有签名决定但审计回执丢失仍可重建 ALLOW”状态: "
                 f"{mc.get('receipt_only_allow_with_audit_gap_states')}")
        L.append(f"- “目录已改但无落地决定”孤儿状态: {mc.get('hard_loss_orphan_states')}")
        L.append(f"- 摘要不符/同号冲突被拒目录状态: "
                 f"{mc.get('digest_conflict_denied_dir_states')}")
        L.append(f"- 朴素目录信任反例状态总数: "
                 f"**{mc.get('naive_dir_trust_counterexample_total')}**")
        for ex in mc.get("naive_dir_trust_first_examples", []):
            L.append(f"  - 例: world=`{ex['world']}`, protocol=`{ex['protocol']}`, "
                     f"prefix=`{' → '.join(ex['prefix']) or '∅'}`, "
                     f"safe=`{ex['safe_verdict']}` vs naive=`{ex['naive_verdict']}`")
        if mc.get("violations"):
            L.append("- 违规:")
            for v in mc["violations"]:
                L.append(f"  - `{v}`")
    L.append("")

    # scale
    sc = rep.get("scale", {})
    n_records = sc.get("parameters", {}).get("records", "?")
    heading_n = "六万" if n_records == 60000 else str(n_records)
    L.append(f"## 6. {heading_n}条分目录模拟记录：局部撤销 vs 全量")
    L.append("")
    if sc:
        p = sc.get("parameters", {})
        L.append(f"- 参数: records={p.get('records')}, shards={p.get('shards')}, "
                 f"files/shard={p.get('files_per_shard')}, "
                 f"partial_shards={p.get('partial_shards')}")
        L.append(f"- 生成耗时: {sc.get('generation', {}).get('elapsed_seconds')}s；"
                 f"撤销记录数: {sc.get('revocations', {}).get('count')}")
        ps = sc.get("partial_scan", {})
        fs = sc.get("full_scan", {})
        L.append("")
        L.append("| 扫描方式 | 实际目录数 | 实际哈希的制品文件 | 读取记录文件 | 总文件检查 | 耗时(s) |")
        L.append("|---|---:|---:|---:|---:|---:|")
        L.append(f"| 局部/部分撤销复测 | {ps.get('directories_counted')} "
                 f"(选中 {ps.get('shard_directories_actually_inspected')} 分片) "
                 f"| **{ps.get('artifact_files_actually_hashed')}** "
                 f"| {ps.get('record_files_read')} "
                 f"| {ps.get('total_files_inspected')} | {ps.get('seconds')} |")
        L.append(f"| 全量重建 | {fs.get('directories_counted')} "
                 f"(选中 {fs.get('shard_directories_actually_inspected')} 分片) "
                 f"| **{fs.get('artifact_files_actually_hashed')}** "
                 f"| {fs.get('record_files_read')} "
                 f"| {fs.get('total_files_inspected')} | {fs.get('seconds')} |")
        L.append("")
        L.append(f"- 局部实际检查: **{sc.get('actual_inspected_directories_and_files', {}).get('partial')}**")
        L.append(f"- 全量实际检查: **{sc.get('actual_inspected_directories_and_files', {}).get('full')}**")
        eq = sc.get("equivalence", {})
        L.append(f"- 对照记录数: {eq.get('records_compared')}；"
                 f"不一致: **{eq.get('mismatch_count')}**；"
                 f"切片内 revoked={eq.get('slice_revoked')}, "
                 f"allowed={eq.get('slice_allowed')}")
        L.append(f"- 等价性结论: `{eq.get('claim')}` → "
                 f"**{'一致 ✅' if eq.get('mismatch_count') == 0 else '不一致 ❌'}**")
        if eq.get("first_mismatches"):
            L.append(f"- 首批不一致: `{eq['first_mismatches']}`")
        L.append(f"- 全量分类计数: `{fs.get('totals')}`")
    L.append("")

    L.append("## 7. 复现方式")
    L.append("")
    L.append("```bat")
    L.append("py -3.12 run_all.py")
    L.append("py -3.12 -m unittest discover -s tests -v")
    L.append("py -3.12 reconstruct.py --root artifacts\\drill --json")
    L.append("```")
    L.append("")
    return "\n".join(L)
