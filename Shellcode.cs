using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

//namespace RemoteApi
//{

class LateValue<T>
{
    protected IntPtr pointer;

    public LateValue(IntPtr pointer)
    {
        this.pointer = pointer;
    }

    public virtual void Insert(T value)
    {
        Marshal.StructureToPtr(value, pointer, false);
    }
}
class FakeObject
{
    internal struct FakePointer
    {
        public IntPtr Pointer;
        public byte Type;

        public FakePointer(IntPtr pointer, byte type = 0)
        {
            Pointer = pointer;
            Type = type;
        }
    }

    internal List<FakePointer> targetPointers;
    internal object value;
    //internal byte type;
    public FakeObject(object value)
    {
        this.value = value;
        targetPointers = new List<FakePointer>();
    }
}

struct Shellcode
{
    public readonly IntPtr Buffer;
    public readonly long RemoteAddress;
    public readonly long EntryPoint;
    public readonly int Size;
    public readonly int BufferSize;

    public Shellcode(IntPtr buffer, long remoteAddress, long entryPoint, int size, int bufferSize)
    {
        Buffer = buffer;
        RemoteAddress = remoteAddress;
        EntryPoint = entryPoint;
        Size = size;
        BufferSize = bufferSize;
    }

    public static byte[] AsciiCString(string s)
    {
        byte[] bytes = new byte[s.Length + 1];
        Encoding.ASCII.GetBytes(s, 0, s.Length, bytes, 0);
        return bytes;
    }

    public static int Align(int value, int to)
    {
        int mask = to - 1;
        return (value + mask) & ~mask;
    }
    public static long Align(long value, int to)
    {
        int mask = to - 1;
        return (value + mask) & ~mask;
    }
}

class ShellcodeMacro
{
    public delegate void Macro(Shellcode86 shellcode, object parameter);
}

class Shellcode86
{
    protected IntPtr startPointer;
    protected IntPtr currentPointer;
    protected int entryPoint;
    public int RemoteAddress;
    protected int size;
    public int MaxSize;
    protected List<FakeObject> fakeMemory;

    protected Shellcode86() { }
    public Shellcode86(IntPtr startPointer, int maxSize, int remoteAddress)
    {
        this.startPointer = startPointer;
        this.currentPointer = startPointer;
        this.RemoteAddress = remoteAddress;
        this.entryPoint = remoteAddress;
        this.size = 0;
        this.MaxSize = maxSize;
        this.fakeMemory = new List<FakeObject>();
    }
    public Shellcode86(IntPtr startPointer, int maxSize, IntPtr remoteAddress) : this(startPointer, maxSize, remoteAddress.ToInt32()) { }

    public Shellcode86 Reset()
    {
        this.currentPointer = startPointer;
        this.entryPoint = RemoteAddress;
        this.size = 0;
        fakeMemory.Clear();

        return this;
    }


    protected void write<T>(T value)
    {
        var valueType = value.GetType();
        int valueSize;
        int newSize;
        if (valueType.IsArray)
        {
            Array arrayValue = value as Array;
            int elementSize = Marshal.SizeOf(valueType.GetElementType());
            valueSize = elementSize * arrayValue.Length;

            newSize = size + valueSize;
            if (newSize > MaxSize) throw new IndexOutOfRangeException();

            IntPtr elementPtr = currentPointer;
            foreach (var item in arrayValue)
            {
                Marshal.StructureToPtr(item, elementPtr, false);
                elementPtr = elementPtr + elementSize;
            }
        }
        else
        {
            valueSize = Marshal.SizeOf(value);

            newSize = size + valueSize;
            if (newSize > MaxSize) throw new IndexOutOfRangeException();

            Marshal.StructureToPtr(value, currentPointer, false);
        }


        currentPointer += valueSize;
        size = newSize;
    }
    protected void insert<T>(IntPtr pointer, T value)
    {
        Marshal.StructureToPtr(value, pointer, false);
    }

    //no inherit
    public int GetCurrentEntryPoint() { return entryPoint; }
    //no inherit
    public int GetCurrentCodeSize() { return size; }
    //no inherit
    public int GetCurrentCodePoint() { return RemoteAddress + size; }
    //no inherit
    public Shellcode86 SetEntryPoint()
    {
        entryPoint = RemoteAddress + size;
        return this;
    }


    public Shellcode86 DebugBreak()
    {
        write<byte>(0xCC);
        return this;
    }

    public Shellcode86 PushRegisterA()
    {
        write<byte>(0x50);
        return this;
    }
    public Shellcode86 PopRegisterA()
    {
        write<byte>(0x58);
        return this;
    }
    public Shellcode86 PushRegisterC()
    {
        write<byte>(0x51);
        return this;
    }
    public Shellcode86 PopRegisterC()
    {
        write<byte>(0x59);
        return this;
    }
    public Shellcode86 PushRegisterD()
    {
        write<byte>(0x52);
        return this;
    }
    public Shellcode86 PopRegisterD()
    {
        write<byte>(0x5A);
        return this;
    }
    public Shellcode86 PushRegisterB()
    {
        write<byte>(0x53);
        return this;
    }
    public Shellcode86 PopRegisterB()
    {
        write<byte>(0x5B);
        return this;
    }

    public Shellcode86 CallRegisterA()
    {
        write<ushort>(0xD0FF); //FF D0
        return this;
    }
    public Shellcode86 JmpRegisterA()
    {
        write<ushort>(0xE0FF); //FF E0
        return this;
    }

    public Shellcode86 MovIntRegisterA(int value)
    {
        write<byte>(0xB8);
        write<int>(value);
        return this;
    }

    public Shellcode86 PushByte(byte value)
    {
        write<byte>(0x6A);
        write<byte>(value);
        return this;
    }

    public Shellcode86 PushInt(int value)
    {
        write<byte>(0x68);
        write<int>(value);
        return this;
    }
    public Shellcode86 PushInt(IntPtr value) { return PushInt(value.ToInt32()); }

    //no inherit
    public Shellcode86 CallFar(int address)
    {
        long delta = (long)address - (RemoteAddress + size + sizeof(int));
        if (delta > int.MaxValue || delta < int.MinValue)
        {
            MovIntRegisterA(address);
            CallRegisterA();
        }
        else
        {
            write<byte>(0xE8);
            write<int>((int)delta);
        }
        return this;
    }
    public Shellcode86 CallFar(IntPtr address) { return CallFar(address.ToInt32()); }

    //no inherit
    public Shellcode86 JumpFar(int address)
    {
        long delta = (long)address - (RemoteAddress + size + sizeof(int));
        if (delta > int.MaxValue || delta < int.MinValue)
        {
            MovIntRegisterA(address);
            JmpRegisterA();
        }
        else
        {
            write<byte>(0xE9);
            write<int>((int)delta);
        }
        return this;
    }
    public Shellcode86 JumpFar(IntPtr address) { return JumpFar(address.ToInt32()); }

    public FakeObject NewFakeObject(object value)
    {
        FakeObject fakeObject = new FakeObject(value);
        fakeMemory.Add(fakeObject);
        return fakeObject;
    }
    public Shellcode86 NewFakeObject(object value, out FakeObject fakeObject)
    {
        fakeObject = NewFakeObject(value);
        return this;
    }

    public Shellcode86 PushFakePointer(FakeObject fakeObject)
    {
        PushInt(0);
        fakeObject.targetPointers.Add(new FakeObject.FakePointer(currentPointer - sizeof(int)));
        return this;
    }

    public Shellcode86 ApplyMacro(/*ShellcodeMacro macroBase, */ShellcodeMacro.Macro macroFunc, object parameter = null)
    {
        macroFunc(this, parameter);
        return this;
    }


    //no inherit
    public Shellcode Complete()
    {
        foreach (FakeObject fakeObject in fakeMemory)
        {
            int objectRemoteAddress = RemoteAddress + size;
            write(fakeObject.value);
            foreach (var targetPointer in fakeObject.targetPointers)
            {
                insert<int>(targetPointer.Pointer, objectRemoteAddress);
            }
        }

        return new Shellcode(startPointer, RemoteAddress, entryPoint, size, MaxSize);
    }
}

class Shellcode64 : Shellcode86
{
    new long entryPoint;
    new public long RemoteAddress;

    public Shellcode64(IntPtr startPointer, int maxSize, long remoteAddress)
    {
        this.startPointer = startPointer;
        this.currentPointer = startPointer;
        this.RemoteAddress = remoteAddress;
        this.entryPoint = remoteAddress;
        this.size = 0;
        this.MaxSize = maxSize;
        this.fakeMemory = new List<FakeObject>();
    }
    public Shellcode64(IntPtr startPointer, int maxSize, IntPtr remoteAddress) : this(startPointer, maxSize, remoteAddress.ToInt64()) { }

    new public Shellcode64 Reset()
    {
        this.currentPointer = startPointer;
        this.entryPoint = RemoteAddress;
        this.size = 0;
        fakeMemory.Clear();

        return this;
    }

    new public long GetCurrentEntryPoint() { return entryPoint; }
    new public long GetCurrentCodeSize() { return size; }
    new public long GetCurrentCodePoint() { return RemoteAddress + size; }
    new public Shellcode64 SetEntryPoint()
    {
        entryPoint = RemoteAddress + size;
        return this;
    }

    new public Shellcode64 DebugBreak()
    {
        base.DebugBreak();
        return this;
    }

    new public Shellcode64 PushRegisterA()
    {
        base.PushRegisterA();
        return this;
    }
    new public Shellcode64 PopRegisterA()
    {
        base.PopRegisterA();
        return this;
    }
    new public Shellcode64 PushRegisterC()
    {
        base.PushRegisterC();
        return this;
    }
    new public Shellcode64 PopRegisterC()
    {
        base.PopRegisterC();
        return this;
    }
    new public Shellcode64 PushRegisterD()
    {
        base.PushRegisterD();
        return this;
    }
    new public Shellcode64 PopRegisterD()
    {
        base.PopRegisterD();
        return this;
    }
    new public Shellcode64 PushRegisterB()
    {
        base.PushRegisterB();
        return this;
    }
    new public Shellcode64 PopRegisterB()
    {
        base.PopRegisterB();
        return this;
    }

    new public Shellcode64 CallRegisterA()
    {
        base.CallRegisterA();
        return this;
    }
    new public Shellcode64 JmpRegisterA()
    {
        base.JmpRegisterA();
        return this;
    }

    //public Shellcode64 MovIntRegister8(int value)
    //{
    //    write<byte>(0x49);
    //    write<ushort>(0xC0C7); //49 C7 C0
    //    write<int>(value);
    //}
    public Shellcode64 MovInt64RegisterA(long value)
    {
        write<ushort>(0xB848); //48 B8
        write<long>(value);
        return this;
    }
    public Shellcode64 MovInt64RegisterA(IntPtr value) { return MovInt64RegisterA(value.ToInt64()); }

    public Shellcode64 MovInt64RegisterC(long value)
    {
        write<ushort>(0xB948); //48 B9
        write<long>(value);
        return this;
    }
    public Shellcode64 MovInt64RegisterC(IntPtr value) { return MovInt64RegisterC(value.ToInt64()); }
    public LateValue<long> MovLateInt64RegisterC()
    {
        MovInt64RegisterC(0);
        return newLateInt64();
    }
    public Shellcode64 MovLateInt64RegisterC(out LateValue<long> lateValue)
    {
        lateValue = MovLateInt64RegisterC();
        return this;
    }

    public Shellcode64 MovInt64RegisterD(long value)
    {
        write<ushort>(0xBA48); //48 BA
        write<long>(value);
        return this;
    }
    public Shellcode64 MovInt64RegisterD(IntPtr value) { return MovInt64RegisterD(value.ToInt64()); }
    public LateValue<long> MovLateInt64RegisterD()
    {
        MovInt64RegisterD(0);
        return newLateInt64();
    }
    public Shellcode64 MovLateInt64RegisterD(out LateValue<long> lateValue)
    {
        lateValue = MovLateInt64RegisterD();
        return this;
    }

    public Shellcode64 MovInt64RegisterB(long value)
    {
        write<ushort>(0xBB48); //48 BB
        write<long>(value);
        return this;
    }
    public Shellcode64 MovInt64RegisterB(IntPtr value) { return MovInt64RegisterB(value.ToInt64()); }

    public Shellcode64 MovInt64Register8(long value)
    {
        write<ushort>(0xB849); //49 B8
        write<long>(value);
        return this;
    }
    public LateValue<long> MovLateInt64Register8()
    {
        MovInt64Register8(0);
        return newLateInt64();
    }
    public Shellcode64 MovLateInt64Register8(out LateValue<long> lateValue)
    {
        lateValue = MovLateInt64Register8();
        return this;
    }
    public Shellcode64 MovInt64Register9(long value)
    {
        write<ushort>(0xB949); //49 B9
        write<long>(value);
        return this;
    }
    public LateValue<long> MovLateInt64Register9()
    {
        MovInt64Register9(0);
        return newLateInt64();
    }
    public Shellcode64 MovLateInt64Register9(out LateValue<long> lateValue)
    {
        lateValue = MovLateInt64Register9();
        return this;
    }
    public Shellcode64 MovRegisterAtoC()
    {
        write<byte>(0x48);
        write<ushort>(0xC189); //48 89 C1
        return this;
    }
    public Shellcode64 MovRegisterAtoD()
    {
        write<byte>(0x48);
        write<ushort>(0xC289); //48 89 C2
        return this;
    }

    public Shellcode64 MovRegisterSPtoD()
    {
        write<byte>(0x48);
        write<ushort>(0xE289); //48 89 E2
        return this;
    }

    //public Shellcode64 MovRegisterAtoFSOffset(int offset)
    //{
    //    write<uint>(0x04894864);
    //    write<byte>(0x25); //64 48 89 04 25
    //    write<int>(offset);
    //    return this;
    //}
    //public Shellcode64 MovRegisterSPtoFSOffset(int offset)
    //{
    //    write<uint>(0x24894864);
    //    write<byte>(0x25); //64 48 89 24 25
    //    write<int>(offset);
    //    return this;
    //}
    //public Shellcode64 MovRegisterSPtoGSOffset(int offset)
    //{
    //    write<uint>(0x24894865);
    //    write<byte>(0x25); //65 48 89 24 25
    //    write<int>(offset);
    //    return this;
    //}

    private void addFakePointer(FakeObject fakeObject)
    {
        fakeObject.targetPointers.Add(new FakeObject.FakePointer(currentPointer - sizeof(long)));
    }
    private LateValue<long> newLateInt64()
    {
        return new LateValue<long>(currentPointer - 8);
    }
    public Shellcode64 MovFakePointerRegisterC(FakeObject fakeObject)
    {
        MovInt64RegisterC(0);
        addFakePointer(fakeObject);
        return this;
    }
    public Shellcode64 MovFakePointerRegisterD(FakeObject fakeObject)
    {
        MovInt64RegisterD(0);
        addFakePointer(fakeObject);
        return this;
    }
    public Shellcode64 MovFakePointerRegister8(FakeObject fakeObject)
    {
        MovInt64Register8(0);
        addFakePointer(fakeObject);
        return this;
    }
    public Shellcode64 MovFakePointerRegister9(FakeObject fakeObject)
    {
        MovInt64Register9(0);
        addFakePointer(fakeObject);
        return this;
    }
    public Shellcode64 MovRegisterAPointer(long pointer)
    {
        write<ushort>(0xA348); //48 A3
        write<long>(pointer);
        return this;
    }
    public Shellcode64 MovRegisterAFakePointer(FakeObject fakeObject)
    {
        MovRegisterAPointer(0);
        addFakePointer(fakeObject);
        return this;
    }
    public LateValue<long> MovRegisterALatePointer()
    {
        MovRegisterAPointer(0);
        return newLateInt64();
    }
    public Shellcode64 MovRegisterALatePointer(out LateValue<long> latePointer)
    {
        latePointer = MovRegisterALatePointer();
        return this;
    }

    new public Shellcode64 PushByte(byte value)
    {
        base.PushByte(value);
        return this;
    }

    public Shellcode64 PushInt64(long value)
    {
        int lo = (int)(value & 0xffffffff);
        int hi = (int)(value >> 32);
        PushInt(lo);
        write<uint>(0x042444C7); //C7 44 24 04
        write<int>(hi);
        return this;
    }
    public Shellcode64 PushInt64(IntPtr value) { return PushInt64(value.ToInt64()); }

    private class LateInt64Push : LateValue<long>
    {
        public LateInt64Push(IntPtr pointer) : base(pointer) { }

        public override void Insert(long value)
        {
            int lo = (int)(value & 0xffffffff);
            int hi = (int)(value >> 32);

            Marshal.StructureToPtr(lo, pointer, false);
            Marshal.StructureToPtr(hi, pointer + 8, false);
        }
    }
    public LateValue<long> PushLateInt64()
    {
        PushInt64(0);
        return new LateInt64Push(currentPointer - 12);
    }
    public Shellcode64 PushLateInt64(out LateValue<long> lateValue)
    {
        lateValue = PushLateInt64();
        return this;
    }

    new public Shellcode64 PushFakePointer(FakeObject fakeObject)
    {
        PushInt64(0);
        fakeObject.targetPointers.Add(new FakeObject.FakePointer(currentPointer - 12, 1));
        return this;
    }

    public Shellcode64 CallFar(long address)
    {
        long delta = address - (RemoteAddress + size + sizeof(int));
        if (delta > int.MaxValue || delta < int.MinValue)
        {
            MovInt64RegisterA(address);
            CallRegisterA();
        }
        else
        {
            write<byte>(0xE8);
            write<int>((int)delta);
        }

        return this;
    }
    new public Shellcode64 CallFar(IntPtr address) { return CallFar(address.ToInt64()); }

    public Shellcode64 JmpFar(long address)
    {
        long delta = (long)address - (RemoteAddress + size + sizeof(int));
        if (delta > int.MaxValue || delta < int.MinValue)
        {
            MovInt64RegisterA(address);
            JmpRegisterA();
        }
        else
        {
            write<byte>(0xE9);
            write<int>((int)delta);
        }

        return this;
    }
    public Shellcode64 JmpFar(IntPtr address) { return JmpFar(address.ToInt64()); }

    new public Shellcode64 NewFakeObject(object value, out FakeObject fakeObject)
    {
        fakeObject = NewFakeObject(value);
        return this;
    }

    public Shellcode64 FakePushBytes(byte count)
    {
        write<int>(0x00EC8348 | (count << 24)); //48 83 EC
        return this;
    }
    public Shellcode64 FakePopBytes(byte count)
    {
        write<int>(0x00C48348 | (count << 24)); //48 83 C4
        return this;
    }

    public Shellcode64 AlignStack()
    {
        write<uint>(0xF0E48348); //48 83 E4 F0
        return this;
    }

    new public Shellcode64 ApplyMacro(/*ShellcodeMacro macroBase, */ShellcodeMacro.Macro macroFunc, object parameter = null)
    {
        macroFunc(this, parameter);
        return this;
    }


    new public Shellcode Complete()
    {
        foreach (FakeObject fakeObject in fakeMemory)
        {
            long objectRemoteAddress = RemoteAddress + size;
            int lo = (int)(objectRemoteAddress & 0xffffffff);
            int hi = (int)(objectRemoteAddress >> 32);
            write(fakeObject.value);
            foreach (var targetPointer in fakeObject.targetPointers)
            {
                if (targetPointer.Type == 1)
                {
                    insert<int>(targetPointer.Pointer, lo);
                    insert<int>(targetPointer.Pointer + 8, hi);
                }
                else
                {
                    insert<long>(targetPointer.Pointer, objectRemoteAddress);
                }
            }
        }

        return new Shellcode(startPointer, RemoteAddress, entryPoint, size, MaxSize);
    }
}


//}
