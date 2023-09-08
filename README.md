# Guard Pages Hooking

C# PoC of Guard Pages hooking, also known as VEH (Vectored Exception Handling) hooking. It is a type of API hooking which can be achieved from userland and does not require patching.

In this example, the hooked function is CloseWindowStation in User32.dll. The function "handler_function" checks it is an exception related to Guard Pages and calls MessageBox, but you can call any code there.

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/guardpages/Screenshot_1.png)
