package com.wwb.pairip;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.backend.unicorn.Hook;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebuggerType;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class pairip {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass VMRunner;
    private final Memory memory;

    pairip(){
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.openai.chatgpt")
                .addBackendFactory(new Unicorn2Factory(true))
                .build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        memory = emulator.getMemory(); // 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解析

        memory.addHookListener(new HookListener() {
            @Override
            public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
                if(libraryName.equals("libc.so")){
                    switch (symbolName){
                        case "__system_property_read_callback":
                            return svcMemory.registerSvc(new Arm64Svc() {
                                @Override
                                public long handle(Emulator<?> emulator) {
                                    System.out.println("__system_property_read_callback called from： "+emulator.getContext().getLRPointer().toString());
                                    return 0;
                                }
                            }).peer;
                        case "malloc":
                        case "alloc":
                            return svcMemory.registerSvc(new Arm64Hook() {
                                @Override
                                protected HookStatus hook(Emulator<?> emulator) {
                                    System.out.println("malloc from:"+emulator.getContext().getLRPointer().toString());
                                    return HookStatus.RET(emulator,old);
                                }
                            }).peer;
                    }
                }
                return 0;
            }
        });

        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        vm = emulator.createDalvikVM(); // 创建Android虚拟机
        vm.setVerbose(true); // 设置是否打印Jni调用细节
        vm.setJni(new AbstractJni() {
        });
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/libpairip/libpairipcore.so"), false); // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数
        dm.callJNI_OnLoad(emulator); // 手动执行JNI_OnLoad函数
        module = dm.getModule(); // 加载好的libttEncrypt.so对应为一个模块

        VMRunner = vm.resolveClass("com/pairip/VMRunner");
    }

    public static void main(String[] args) throws Exception {
        pairip test = new pairip();

        test.run();
//        Inspector.inspect(data, "ttEncrypt");

        test.destroy();
    }

    private void run() throws IOException {
        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(memory.findModule("libc.so"),0x5BA18);
        debugger.addBreakPoint(module,0x1BADC);
        byte[] data = Files.readAllBytes(new File("unidbg-android/src/test/resources/example_binaries/libpairip/H0BtU0Puf96KFtfn").toPath());
        VMRunner.callStaticJniMethod(emulator,"executeVM([B[Ljava/lang/Object;)Ljava/lang/Object;", (Object) data,null);
    }

    void destroy() {
        IOUtils.close(emulator);
        System.out.println("destroy");
    }
}
