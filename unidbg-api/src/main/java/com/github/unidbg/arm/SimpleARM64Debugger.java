package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.Utils;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.FunctionCallListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.RunnableTask;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneMode;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import unicorn.Arm64Const;

import java.util.Objects;
import java.util.Scanner;

class SimpleARM64Debugger extends AbstractARMDebugger implements Debugger {

    SimpleARM64Debugger(Emulator<?> emulator) {
        super(emulator);
    }

    @Override
    public void traceFunctionCall(Module module, FunctionCallListener listener) {
        Backend backend = emulator.getBackend();
        TraceFunctionCall hook = new TraceFunctionCall64(emulator, listener);
        long begin = module == null ? 1 : module.base;
        long end = module == null ? 0 : module.base + module.size;
        backend.hook_add_new(hook, begin, end, emulator);
    }

    @Override
    protected final void loop(Emulator<?> emulator, long address, int size, DebugRunnable<?> runnable) throws Exception {
        Backend backend = emulator.getBackend();
        long nextAddress = 0;

        try {
            if (address != -1) {
                RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
                System.out.println("debugger break at: 0x" + Long.toHexString(address) + (runningTask == null ? "" : (" @ " + runningTask)));
                emulator.showRegs();
            }
            if (address > 0) {
                nextAddress = disassemble(emulator, address, size, false);
            }
        } catch (BackendException e) {
            e.printStackTrace(System.err);
        }

        Scanner scanner = new Scanner(System.in);
        String line;
        while ((line = scanner.nextLine()) != null) {
            line = line.trim();
            try {
                if ("help".equals(line)) {
                    showHelp(address);
                    continue;
                }
                if (line.startsWith("run") && runnable != null) {
                    try {
                        callbackRunning = true;
                        String arg = line.substring(3).trim();
                        if (arg.length() > 0) {
                            String[] args = arg.split("\\s+");
                            runnable.runWithArgs(args);
                        } else {
                            runnable.runWithArgs(null);
                        }
                    } finally {
                        callbackRunning = false;
                    }
                    continue;
                }
                if ("d".equals(line) || "dis".equals(line)) {
                    emulator.showRegs();
                    disassemble(emulator, address, size, false);
                    continue;
                }
                if (line.startsWith("d0x")) {
                    if (line.endsWith("L")) {
                        line = line.substring(0, line.length() - 1);
                    }
                    long da = Long.parseLong(line.substring(3), 16);
                    disassembleBlock(emulator, da & 0xfffffffffffffffcL, false);
                    continue;
                }
                if (line.startsWith("m")) {
                    String command = line;
                    String[] tokens = line.split("\\s+");
                    int length = 0x70;
                    try {
                        if (tokens.length >= 2) {
                            command = tokens[0];
                            String str = tokens[1];
                            length = (int) Utils.parseNumber(str);
                        }
                    } catch(NumberFormatException ignored) {}
                    StringType stringType = null;
                    if (command.endsWith("s")) {
                        stringType = StringType.nullTerminated;
                        command = command.substring(0, command.length() - 1);
                    } else if (command.endsWith("std")) {
                        stringType = StringType.std_string;
                        command = command.substring(0, command.length() - 3);
                    }

                    int reg = -1;
                    String name = null;
                    if (command.startsWith("mx") && (command.length() == 3 || command.length() == 4)) {
                        int idx = Integer.parseInt(command.substring(2));
                        if (idx >= 0 && idx <= 28) {
                            reg = Arm64Const.UC_ARM64_REG_X0 + idx;
                            name = "x" + idx;
                        }
                    } else if ("mfp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_FP;
                        name = "fp";
                    } else if ("mip".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_IP0;
                        name = "ip";
                    } else if ("msp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_SP;
                        name = "sp";
                    } else if (command.startsWith("m0x")) {
                        String hex = command.substring(3).trim();
                        if (hex.endsWith("L")) {
                            hex = hex.substring(0, hex.length() - 1);
                        }
                        long addr = Long.parseLong(hex, 16);
                        Pointer pointer = UnidbgPointer.pointer(emulator, addr);
                        if (pointer != null) {
                            dumpMemory(pointer, length, pointer.toString(), stringType);
                        } else {
                            System.out.println(addr + " is null");
                        }
                        continue;
                    }
                    if (reg != -1) {
                        Pointer pointer = UnidbgPointer.register(emulator, reg);
                        if (pointer != null) {
                            dumpMemory(pointer, length, name + "=" + pointer, stringType);
                        } else {
                            System.out.println(name + " is null");
                        }
                        continue;
                    }
                }
                if ("where".equals(line)) {
                    new Exception("here").printStackTrace(System.out);
                    continue;
                }
                if (line.startsWith("wx0x")) {
                    String[] tokens = line.split("\\s+");
                    String hex = tokens[0].substring(4).trim();
                    if (hex.endsWith("L")) {
                        hex = hex.substring(0, hex.length() - 1);
                    }
                    long addr = Long.parseLong(hex, 16);
                    Pointer pointer = UnidbgPointer.pointer(emulator, addr);
                    if (pointer != null && tokens.length > 1) {
                        byte[] data = Hex.decodeHex(tokens[1].toCharArray());
                        pointer.write(0, data, 0, data.length);
                        dumpMemory(pointer, data.length, pointer.toString(), null);
                    } else {
                        System.out.println(addr + " is null");
                    }
                    continue;
                }
                if (line.startsWith("w")) {
                    String command;
                    String[] tokens = line.split("\\s+");
                    if (tokens.length < 2) {
                        System.out.println("wx0-wx28, wfp, wip, wsp <value>: write specified register");
                        System.out.println("wb(address), ws(address), wi(address), wl(address) <value>: write (byte, short, integer, long) memory of specified address, address must start with 0x");
                        continue;
                    }
                    long value;
                    try {
                        command = tokens[0];
                        String str = tokens[1];
                        value = Utils.parseNumber(str);
                    } catch(NumberFormatException e) {
                        e.printStackTrace(System.err);
                        continue;
                    }

                    int reg = -1;
                    if (command.startsWith("wx") && (command.length() == 3 || command.length() == 4)) {
                        int idx = Integer.parseInt(command.substring(2));
                        if (idx >= 0 && idx <= 28) {
                            reg = Arm64Const.UC_ARM64_REG_X0 + idx;
                        }
                    } else if ("wfp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_FP;
                    } else if ("wip".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_IP0;
                    } else if ("wsp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_SP;
                    } else if (command.startsWith("wb0x") || command.startsWith("ws0x") || command.startsWith("wi0x") || command.startsWith("wl0x")) {
                        String hex = command.substring(4).trim();
                        if (hex.endsWith("L")) {
                            hex = hex.substring(0, hex.length() - 1);
                        }
                        long addr = Long.parseLong(hex, 16);
                        Pointer pointer = UnidbgPointer.pointer(emulator, addr);
                        if (pointer != null) {
                            if (command.startsWith("wb")) {
                                pointer.setByte(0, (byte) value);
                            } else if (command.startsWith("ws")) {
                                pointer.setShort(0, (short) value);
                            } else if (command.startsWith("wi")) {
                                pointer.setInt(0, (int) value);
                            } else if (command.startsWith("wl")) {
                                pointer.setLong(0, value);
                            }
                            dumpMemory(pointer, 16, pointer.toString(), null);
                        } else {
                            System.out.println(addr + " is null");
                        }
                        continue;
                    }
                    if (reg != -1) {
                        backend.reg_write(reg, value);
                        ARM.showRegs64(emulator, new int[] { reg });
                        continue;
                    }
                }
                if (emulator.isRunning() && "bt".equals(line)) {
                    try {
                        emulator.getUnwinder().unwind();
                    } catch (Throwable e) {
                        e.printStackTrace(System.err);
                    }
                    continue;
                }
                if (line.startsWith("b0x")) {
                    try {
                        if (line.endsWith("L")) {
                            line = line.substring(0, line.length() - 1);
                        }
                        long addr = Long.parseLong(line.substring(3), 16) & 0xfffffffffffffffeL;
                        Module module = null;
                        if (addr < Memory.MMAP_BASE && (module = findModuleByAddress(emulator, address)) != null) {
                            addr += module.base;
                        }
                        addBreakPoint(addr); // temp breakpoint
                        if (module == null) {
                            module = findModuleByAddress(emulator, addr);
                        }
                        System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                        continue;
                    } catch(NumberFormatException ignored) {
                    }
                }
                if ("blr".equals(line)) { // break LR
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
                    addBreakPoint(addr);
                    Module module = findModuleByAddress(emulator, addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if ("r".equals(line)) {
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                    if (removeBreakPoint(addr)) {
                        Module module = findModuleByAddress(emulator, addr);
                        System.out.println("Remove breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    }
                    continue;
                }
                if ("b".equals(line)) {
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                    addBreakPoint(addr);
                    Module module = findModuleByAddress(emulator, addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if("bs".equals(line)){
                    long nextfp = backend.reg_read(Arm64Const.UC_ARM64_REG_FP).longValue();
                    while (nextfp!=0){
                        try{
                            long frame = Objects.requireNonNull(UnidbgPointer.pointer(emulator, nextfp + 8)).getLong(0);
                            System.out.println(Objects.requireNonNull(UnidbgPointer.pointer(emulator, frame)));
                            nextfp = Objects.requireNonNull(UnidbgPointer.pointer(emulator, nextfp)).getLong(0);
                        }catch (BackendException e){
                            System.out.println("mem_read 0x"+Long.toHexString(nextfp)+" invalid FP");
                            break;
                        }
                    }
                    continue;
                }
                if(handleCommon(backend, line, address, size, nextAddress, runnable)) {
                    break;
                }
            } catch (RuntimeException | DecoderException e) {
                e.printStackTrace(System.err);
            }
        }
    }

    @Override
    final void showHelp(long address) {
        System.out.println("c: continue");
        System.out.println("n: step over");
        if (emulator.isRunning()) {
            System.out.println("bt: back trace");
        }
        System.out.println("bs: back trace according stack");
        System.out.println();
        System.out.println("st hex: search stack");
        System.out.println("shw hex: search writable heap");
        System.out.println("shr hex: search readable heap");
        System.out.println("shx hex: search executable heap");
        System.out.println();
        System.out.println("nb: break at next block");
        System.out.println("s|si: step into");
        System.out.println("s[decimal]: execute specified amount instruction");
        System.out.println("s(bl): execute util BL mnemonic, low performance");
        System.out.println();
        System.out.println("m(op) [size]: show memory, default size is 0x70, size may hex or decimal");
        System.out.println("mx0-mx28, mfp, mip, msp [size]: show memory of specified register");
        System.out.println("m(address) [size]: show memory of specified address, address must start with 0x");
        System.out.println();
        System.out.println("wx0-wx28, wfp, wip, wsp <value>: write specified register");
        System.out.println("wb(address), ws(address), wi(address), wl(address) <value>: write (byte, short, integer, long) memory of specified address, address must start with 0x");
        System.out.println("wx(address) <hex>: write bytes to memory at specified address, address must start with 0x");
        System.out.println();
        System.out.println("b(address): add temporarily breakpoint, address must start with 0x, can be module offset");
        System.out.println("b: add breakpoint of register PC");
        System.out.println("r: remove breakpoint of register PC");
        System.out.println("blr: add temporarily breakpoint of register LR");
        System.out.println();
        System.out.println("p (assembly): patch assembly at PC address");
        System.out.println("where: show java stack trace");
        System.out.println();
        System.out.println("trace [begin end]: Set trace instructions");
        System.out.println("traceRead [begin end]: Set trace memory read");
        System.out.println("traceWrite [begin end]: Set trace memory write");
        System.out.println("vm: view loaded modules");
        System.out.println("vbs: view breakpoints");
        System.out.println("d|dis: show disassemble");
        System.out.println("d(0x): show disassemble at specify address");
        System.out.println("stop: stop emulation");
        System.out.println("run [arg]: run test");
        System.out.println("gc: Run System.gc()");
        System.out.println("threads: show thread list");

        if (emulator.getFamily() == Family.iOS && !emulator.isRunning()) {
            System.out.println("dump [class name]: dump objc class");
            System.out.println("search [keywords]: search objc classes");
            System.out.println("gpb [class name]: dump GPB protobuf msg def");
        }

        Module module = emulator.getMemory().findModuleByAddress(address);
        if (module != null) {
            System.out.printf("cc (size): convert asm from (0x%x) to (0x%x + size) bytes to c function%n", address, address);
        }
    }

    @Override
    protected Keystone createKeystone(boolean isThumb) {
        return new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
    }

}
