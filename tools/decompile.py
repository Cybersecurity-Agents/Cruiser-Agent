#!/usr/bin/env python
"""PyGhidra 无头反编译工具（供 Claude Code 引擎调用）。

用法:
    python tools/decompile.py <binary>              # 列出全部函数，并反编译 main（若存在）
    python tools/decompile.py <binary> <函数名>      # 反编译名字包含该串的所有函数
    python tools/decompile.py <binary> --all        # 反编译全部函数（输出较大，建议重定向到文件再 grep）
    附加 --no-asm 可只输出伪码（默认同时输出反汇编与数据引用表）

每个函数输出四段：C 伪码 / 数据引用一览 / switch 分派一览（有跳转表时）/ 反汇编。
switch 分派一览会逐个 case 报告其效果，并标出「取数被反编译器消除」的 case——
这类 opcode 的运算没被编译进二进制，是判断『opcode 集合尚未还原完』的直接依据。
数据引用一览会标出「被本函数读取、但伪码中找不到对应表达式」的地址——这通常意味着相关
运算已被编译器当死代码消除（伪码不可信），或被反编译器抽象掉（如 switch 跳转表）。
遇到自研 VM / 字节码混淆时，这类落差往往就是关键线索，不要只看伪码下结论。

环境：脚本内已内置 GHIDRA_INSTALL_DIR / JAVA_HOME 默认值，可用同名环境变量覆盖。
"""
from __future__ import annotations

import os
import sys
import warnings

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra_12.1.2_PUBLIC")
os.environ.setdefault("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64")

warnings.filterwarnings("ignore", category=DeprecationWarning)  # open_program 的弃用提示会干扰输出

import pyghidra  # noqa: E402

_PRINTABLE = range(0x20, 0x7F)


def _read_bytes(flat, addr, n: int):
    """读取 n 字节；不可读（如 .bss 未初始化）时返回 None。"""
    try:
        return bytes(b & 0xFF for b in flat.getBytes(addr, n))
    except Exception:
        return None


def _hex_preview(data: bytes) -> str:
    text = "".join(chr(b) if b in _PRINTABLE else "." for b in data)
    return " ".join(f"{b:02x}" for b in data) + f"  |{text}|"


def _symbol_name(prog, addr):
    sym = prog.getSymbolTable().getPrimarySymbol(addr)
    return sym.getName() if sym is not None else None


def _data_refs(prog, func):
    """函数体内被引用的数据地址 -> 首个引用它的指令地址。"""
    refs = {}
    for instr in prog.getListing().getInstructions(func.getBody(), True):
        for ref in instr.getReferencesFrom():
            if ref.isStackReference() or ref.isExternalReference():
                continue
            if not ref.getReferenceType().isData():
                continue
            to = ref.getToAddress()
            if to is not None and prog.getMemory().contains(to):
                refs.setdefault(to, instr.getAddress())
    return refs


def _visible_in_c(c_text: str, prog, addr, data: bytes | None = None) -> bool:
    """该数据地址是否在伪码里留下了痕迹（符号名、裸地址，或以字符串字面量形式出现）。"""
    low = c_text.lower()
    off = addr.getOffset()
    cands = [f"{off:x}", f"{off:08x}"]
    name = _symbol_name(prog, addr)
    if name:
        cands.append(name)
    if any(c.lower() in low for c in cands):
        return True
    if data:  # 字符串常量在伪码中通常直接内联为字面量，不会出现符号名
        s = data.split(b"\x00", 1)[0]
        if len(s) >= 4 and all(b in _PRINTABLE for b in s):
            return s.decode("ascii", "ignore") in c_text
    return False


def _print_data_refs(
    prog, flat, func, c_text: str, show_asm: bool = True, preview: int = 48, merge_gap: int = 4
) -> None:
    refs = _data_refs(prog, func)
    if not refs:
        return
    # 相邻偏移（同一数组的不同下标）合并为一组，避免 DAT_x+1/+2 这类噪声
    groups: list = []
    for addr in sorted(refs, key=lambda a: a.getOffset()):
        if groups and addr.getOffset() - groups[-1][0].getOffset() <= merge_gap:
            groups[-1][1].append(addr)
        else:
            groups.append((addr, []))

    print("// --- 数据引用一览（地址 / 伪码是否可见 / 内容预览）---")
    hidden = []
    for base, extras in groups:
        name = _symbol_name(prog, base) or "-"
        data = _read_bytes(flat, base, preview)
        if name.lower().startswith("switchdata"):
            status = "跳转表(switch 已抽象)"
        elif _visible_in_c(c_text, prog, base, data):
            status = "是"
        else:
            status = "否  <=="
            hidden.append(base)
        tail = f"   (另含相邻引用 {', '.join(str(a) for a in extras)})" if extras else ""
        print(f"//   {base}  {name:<22}伪码可见:{status:<22}引用自 {refs[base]}{tail}")
        print(f"//       {_hex_preview(data) if data else '(不可读/未初始化)'}")
    if hidden:
        print("// [WARN] 标『否』的数据被本函数读取，但伪码里没有任何对应表达式。常见原因：")
        print("//   (a) 相关运算被编译器当死代码消除 —— 此时伪码不可信，真实变换只能从")
        print("//       数据内容 + 字节码/控制流结构反推，且无论换用哪个反编译器都恢复不出来；")
        print("//   (b) 被反编译器抽象掉（如 switch 的跳转表基址），属正常现象。")
        where = "下方反汇编" if show_asm else "反汇编（去掉 --no-asm 重跑即可看到）"
        print(f"//   若疑似 (a)，切勿断定这些数据无用；请对照{where}确认它们参与了什么运算。")


_BRANCHY = {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN", "CALL", "CALLIND", "CALLOTHER"}


def _reads_stack(instr, sp) -> bool:
    """该指令的内存读是否基于栈指针。PUSH/POP 等寄存器保存恢复属编译器簿记，
    反编译器本就不会为其生成 LOAD，必须排除，否则函数尾声会整片误报。"""
    if sp is None:
        return False
    ops = list(instr.getPcode())
    defs = {}
    for op in ops:
        out = op.getOutput()
        if out is not None:
            defs[str(out)] = op

    def touches_sp(vn, depth: int = 0) -> bool:
        if vn is None or depth > 6:
            return False
        if vn.isRegister() and vn.getAddress() == sp.getAddress():
            return True
        d = defs.get(str(vn))
        return bool(d) and any(touches_sp(i, depth + 1) for i in d.getInputs())

    return any(op.getMnemonic() == "LOAD" and touches_sp(op.getInput(1)) for op in ops)


def _load_dropped(instr, hf, sp) -> bool:
    """原始 pcode 有 LOAD、但反编译器化简后没有 —— 说明这次取数被当死代码消除了。"""
    if _reads_stack(instr, sp):
        return False
    if not any(op.getMnemonic() == "LOAD" for op in instr.getPcode()):
        return False
    return not any(op.getMnemonic() == "LOAD" for op in hf.getPcodeOps(instr.getAddress()))


def _switch_cases(prog, func, hf):
    """{case 入口地址: [分派到它的 case 值]}；无 switch 返回 {}。"""
    cases: dict = {}
    try:  # 优先用反编译器恢复的跳转表，能拿到 case 值（如 0xc1）
        for jt in hf.getJumpTables():
            values = list(jt.getLabelValues() or [])
            for i, a in enumerate(list(jt.getCases() or [])):
                cases.setdefault(a, []).append(values[i] if i < len(values) else None)
    except Exception:
        cases = {}
    if not cases:  # 退化路径：直接取计算跳转的流引用目标
        for instr in prog.getListing().getInstructions(func.getBody(), True):
            ft = instr.getFlowType()
            if ft.isJump() and ft.isComputed():
                for ref in instr.getReferencesFrom():
                    if ref.getReferenceType().isFlow():
                        cases.setdefault(ref.getToAddress(), [])
    return cases


def _case_region(prog, start, stops):
    """从 case 入口顺序取指令；遇汇合点 / 其它 case 入口 / 无条件转移即止。"""
    listing = prog.getListing()
    region = []
    instr = listing.getInstructionAt(start)
    while instr is not None:
        addr = instr.getAddress()
        if region and (addr in stops or sum(
            1 for r in prog.getReferenceManager().getReferencesTo(addr)
            if r.getReferenceType().isFlow()
        ) >= 2):
            break
        region.append(instr)
        ft = instr.getFlowType()
        if ft.isTerminal() or (ft.isJump() and not ft.isConditional()):
            break
        instr = listing.getInstructionAfter(addr)
    return region


def _dispatch_info(prog, func):
    """返回 (计算跳转指令, [分派前的条件分支])。后者通常含越界检查（default 路径）
    与在查表前被单独拦截的特例值，二者都会让某些 opcode 不出现在 case 列表里。"""
    listing = prog.getListing()
    jumps = [i for i in listing.getInstructions(func.getBody(), True)
             if i.getFlowType().isJump() and i.getFlowType().isComputed()]
    if not jumps:
        return None, []
    jmp = jumps[0]
    guards = []
    instr = listing.getInstructionBefore(jmp.getAddress())
    for _ in range(12):
        if instr is None:
            break
        ft = instr.getFlowType()
        if ft.isJump() and ft.isConditional():
            tgts = ",".join(str(r.getToAddress()) for r in instr.getReferencesFrom()
                            if r.getReferenceType().isFlow())
            guards.append(f"{instr.getAddress()}  {instr}" + (f"   -> {tgts}" if tgts else ""))
        # 走到基本块入口（该地址被别处跳入）就停止回溯
        if any(r.getReferenceType().isFlow()
               for r in prog.getReferenceManager().getReferencesTo(instr.getAddress())):
            break
        instr = listing.getInstructionBefore(instr.getAddress())
    return jmp, guards


def _print_switch_cases(prog, func, hf) -> None:
    cases = _switch_cases(prog, func, hf)
    if not cases:
        return
    sp = None
    try:
        sp = prog.getCompilerSpec().getStackPointer()
    except Exception:
        pass
    stops = set(cases)
    print("// --- switch/跳转表分派一览（自研 VM 解释器常见形态）---")
    lost, quiet = [], []
    for target in sorted(cases, key=lambda a: a.getOffset()):
        region = _case_region(prog, target, stops)
        calls, writes, dropped, effects = [], [], [], 0
        for instr in region:
            addr = instr.getAddress()
            ft = instr.getFlowType()
            if ft.isCall():
                calls.append(str(addr))
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType().isWrite():
                    writes.append(str(addr))
            if _load_dropped(instr, hf, sp):
                dropped.append(f"{addr}  {instr}")
            # 只统计非控制转移指令：跳转指令上挂的 COPY 是 SSA 在汇合点的寄存器归并
            # 产物而非真实运算，计入会让下面的「无存活运算」判定永不成立。
            if not (ft.isJump() or ft.isTerminal() or ft.isCall()):
                effects += sum(1 for op in hf.getPcodeOps(addr)
                               if op.getMnemonic() not in _BRANCHY)
        vals = [v for v in cases[target] if v is not None]
        label = ("case " + "/".join(f"0x{int(v):x}" for v in vals)) if vals else "case(值未定)"
        print(f"//   {label} -> {target}  [{len(region)} 条指令]  "
              f"调用:{','.join(calls) or '-'}  写内存:{','.join(writes) or '-'}  "
              f"伪码中存活的运算:{effects}")
        for d in dropped:
            print(f"//       被消除的取数: {d}")
        if dropped:
            lost.append((label, target))
        elif not calls and not writes and effects == 0:
            quiet.append((label, target))
    if lost:
        print("// [WARN] 上列 case 的取数被反编译器消除，其真实语义无法从伪码获得：")
        for label, t in lost:
            print(f"//     {label} -> {t}")
        print("//   这类 opcode 的运算根本没被编译进二进制，换任何反编译器都恢复不出来；")
        print("//   只能结合数据内容与字节码结构反推，再对候选语义做小空间枚举+可打印性校验。")
    if quiet:
        print("// [注] 下列 case 无调用、无内存写、伪码中也无任何存活运算，可能是真 NOP，")
        print("//   也可能其语义未体现在代码中。在判定『opcode 集合已完全还原』前请逐个确认：")
        for label, t in quiet:
            print(f"//     {label} -> {t}")
    covered = sorted({int(v) for vs in cases.values() for v in vs if v is not None})
    if covered:
        print("//   跳转表覆盖的 case 值: " + " ".join(f"0x{v:x}" for v in covered))
    jmp, guards = _dispatch_info(prog, func)
    if jmp is not None:
        print(f"//   分派点: {jmp.getAddress()}  {jmp}")
    for g in guards:
        print(f"//   分派前的条件分支: {g}")
    if covered and guards:
        print("//   [注] 上面这些条件分支会在查表前拦掉部分取值，因此『字节码里出现、但不在覆盖值里』"
              "的 opcode 走的是 default 路径，")
        print("//     它不会出现在 case 列表中，语义同样未确认——务必把字节码用到的每个取值都与覆盖值逐一比对。")


def _print_disasm(prog, func) -> None:
    print("// --- 反汇编（地址与上方伪码一致，便于核对伪码是否丢了运算）---")
    for instr in prog.getListing().getInstructions(func.getBody(), True):
        print(f"//   {instr.getAddress()}  {instr}")


def main() -> int:
    argv = [a for a in sys.argv[1:] if a != "--no-asm"]
    show_asm = "--no-asm" not in sys.argv
    if not argv:
        print(__doc__)
        return 2
    binary = argv[0]
    func_filter = argv[1] if len(argv) > 1 else None
    if not os.path.exists(binary):
        print(f"[ERROR] 文件不存在: {binary}")
        return 1

    pyghidra.start()
    from ghidra.app.decompiler import DecompInterface

    with pyghidra.open_program(binary, analyze=True) as flat:
        prog = flat.getCurrentProgram()
        decomp = DecompInterface()
        try:
            decomp.openProgram(prog)
            fm = prog.getFunctionManager()
            functions = [f for f in fm.getFunctions(True) if not f.isExternal() and not f.isThunk()]

            if func_filter is None:
                # 默认模式：函数清单 + main 反编译
                print(f"// 共 {len(functions)} 个函数（非库函数）:")
                for f in functions:
                    print(f"//   {f.getName()} @ {f.getEntryPoint()}")
                targets = [f for f in functions if f.getName() == "main"]
            elif func_filter == "--all":
                targets = functions
            else:
                targets = [f for f in functions if func_filter in f.getName()]
                if not targets:
                    print(f"[WARN] 没有匹配 '{func_filter}' 的函数，可用函数:")
                    for f in functions:
                        print(f"//   {f.getName()} @ {f.getEntryPoint()}")
                    return 1

            for f in targets:
                res = decomp.decompileFunction(f, 60, None)
                if res and res.getDecompiledFunction():
                    c_text = res.getDecompiledFunction().getC()
                    print(f"\n// ===== {f.getName()} @ {f.getEntryPoint()} =====")
                    print(c_text)
                    _print_data_refs(prog, flat, f, c_text, show_asm)
                    hf = res.getHighFunction()
                    if hf is not None:
                        _print_switch_cases(prog, f, hf)
                    if show_asm:
                        _print_disasm(prog, f)
        finally:
            decomp.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
