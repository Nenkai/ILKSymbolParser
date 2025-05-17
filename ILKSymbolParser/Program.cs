using Syroot.BinaryData;

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;

namespace ILKSymbolParser
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("ILKSymbolParser (for 32bit 14.0.24125 executables)");

            using var sw = new StreamWriter("syms.txt");

            var db = IncrementalLinkerDatabase.Open(args[0]);
            Console.WriteLine($"{db.Image.ST.HT.Entries.Count} entries");

            foreach (var entry in db.Image.ST.HT.Entries.OrderBy(e => e.Value))
            {
                sw.WriteLine($"{db.Image.IMAGE_OPTIONAL_HEADER.ImageBase + (uint)entry.Value:X}\t{entry.Key}");
            }

            Console.WriteLine("saved as syms.txt");
        }
    }

    public class IncrementalLinkerDatabase
    {
        public IMAGE Image { get; private set; } = new IMAGE();

        // Only works with 14.0.24125 (32bit)
        public static IncrementalLinkerDatabase Open(string file)
        {
            using var fs = File.OpenRead(file);
            using var bs = new BinaryStream(fs);

            var incrementalLinkerDatabase = new IncrementalLinkerDatabase();
            incrementalLinkerDatabase.Read(bs);
            return incrementalLinkerDatabase;
        }

        private void Read(BinaryStream bs)
        {
            Image.Read(bs);
        }
    }

    public class IMAGE
    {
        public ushort HeaderSize { get; private set; }
        public ushort Machine { get; private set; }
        public ushort MajVersNum { get; private set; }
        public ushort MinVersNum { get; private set; }
        public ushort BuildVersNum { get; private set; }
        public ushort RevVersNum { get; private set; }
        public uint PvBase { get; private set; }
        public uint CbExe { get; private set; }
        public uint TsExe { get; private set; }
        public IMAGE_FILE_HEADER IMAGE_FILE_HEADER { get; private set; } = new IMAGE_FILE_HEADER();
        public IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER { get; private set; } = new IMAGE_OPTIONAL_HEADER();
        public StringTable ST { get; set; } = new();

        public void Read(BinaryStream bs)
        {
            bs.Position += 32;
            HeaderSize = bs.ReadUInt16();
            Machine = bs.ReadUInt16();
            MajVersNum = bs.ReadUInt16();
            MinVersNum = bs.ReadUInt16();
            BuildVersNum = bs.ReadUInt16();
            RevVersNum = bs.ReadUInt16();
            PvBase = bs.ReadUInt32();
            CbExe = bs.ReadUInt32();
            TsExe = bs.ReadUInt32();
            bs.ReadUInt32();
            bs.ReadUInt32();
            IMAGE_FILE_HEADER.Read(bs);
            IMAGE_OPTIONAL_HEADER.Read(bs);
            bs.ReadUInt32();
            bs.Position += 0xD8; // SWITCH
            bs.Position += 0x40; // SWITCH_INFO
            uint pointer_0x260 = bs.ReadUInt32() - PvBase;
            uint pointer_0x264 = bs.ReadUInt32() - PvBase;
            uint pointer_0x268 = bs.ReadUInt32() - PvBase;
            uint pointer_0x26C = bs.ReadUInt32() - PvBase;
            int field_0x270 = bs.ReadInt32();
            uint pointer_0x274 = bs.ReadUInt32() - PvBase;
            uint pointer_0x278 = bs.ReadUInt32() - PvBase;
            uint pExternalSymbolTable = bs.ReadUInt32() - PvBase;
            uint pointer_0x280 = bs.ReadUInt32() - PvBase;
            // DosHeaderArray? 
            // TODO

            bs.Position = pExternalSymbolTable;
            ST.Read(bs, this);
        }
    }

    public class IMAGE_FILE_HEADER
    {
        public ushort Machine { get; private set; }
        public ushort NumberOfSections { get; private set; }
        public uint TimeDateStamp { get; private set; }
        public uint PointerToSymbolTable { get; private set; }
        public uint NumberOfSymbols { get; private set; }
        public ushort SizeOfOptionalHeader { get; private set; }
        public ushort Characteristics { get; private set; }

        public void Read(BinaryStream bs)
        {
            Machine = bs.ReadUInt16();
            NumberOfSections = bs.ReadUInt16();
            TimeDateStamp = bs.ReadUInt32();
            PointerToSymbolTable = bs.ReadUInt32();
            NumberOfSymbols = bs.ReadUInt32();
            SizeOfOptionalHeader = bs.ReadUInt16();
            Characteristics = bs.ReadUInt16();
        }
    }

    public class IMAGE_OPTIONAL_HEADER
    {
        public ushort Magic { get; private set; }
        public byte MajorLinkerVersion { get; private set; }
        public byte MinorLinkerVersion { get; private set; }
        public uint SizeOfCode { get; private set; }
        public uint SizeOfInitializedData { get; private set; }
        public uint SizeOfUninitializedData { get; private set; }
        public uint AddressOfEntryPoint { get; private set; }
        public uint BaseOfCode { get; private set; }
        public ulong ImageBase { get; private set; }
        public uint SectionAlignment { get; private set; }
        public uint FileAlignment { get; private set; }
        public ushort MajorOperatingSystemVersion { get; private set; }
        public ushort MinorOperatingSystemVersion { get; private set; }
        public ushort MajorImageVersion { get; private set; }
        public ushort MinorImageVersion { get; private set; }
        public ushort MajorSubsystemVersion { get; private set; }
        public ushort MinorSubsystemVersion { get; private set; }
        public uint Win32VersionValue { get; private set; }
        public uint SizeOfImage { get; private set; }
        public uint SizeOfHeaders { get; private set; }
        public uint CheckSum { get; private set; }
        public ushort Subsystem { get; private set; }
        public ushort DllCharacteristics { get; private set; }
        public ulong SizeOfStackReserve { get; private set; }
        public ulong SizeOfStackCommit { get; private set; }
        public ulong SizeOfHeapReserve { get; private set; }
        public ulong SizeOfHeapCommit { get; private set; }
        public uint LoaderFlags { get; private set; }
        public uint NumberOfRvaAndSizes { get; private set; }
        public IMAGE_DATA_DIRECTORY[] DataDirectory { get; private set; } = new IMAGE_DATA_DIRECTORY[16];

        public void Read(BinaryStream bs)
        {
            Magic = bs.ReadUInt16();
            MajorLinkerVersion = bs.Read1Byte();
            MinorLinkerVersion = bs.Read1Byte();
            SizeOfCode = bs.ReadUInt32();
            SizeOfInitializedData = bs.ReadUInt32();
            SizeOfUninitializedData = bs.ReadUInt32();
            AddressOfEntryPoint = bs.ReadUInt32();
            BaseOfCode = bs.ReadUInt32();
            ImageBase = bs.ReadUInt64();
            SectionAlignment = bs.ReadUInt32();
            FileAlignment = bs.ReadUInt32();
            MajorOperatingSystemVersion = bs.ReadUInt16();
            MinorOperatingSystemVersion = bs.ReadUInt16();
            MajorImageVersion = bs.ReadUInt16();
            MinorImageVersion = bs.ReadUInt16();
            MajorSubsystemVersion = bs.ReadUInt16();
            MinorSubsystemVersion = bs.ReadUInt16();
            Win32VersionValue = bs.ReadUInt32();
            SizeOfImage = bs.ReadUInt32();
            SizeOfHeaders = bs.ReadUInt32();
            CheckSum = bs.ReadUInt32();
            Subsystem = bs.ReadUInt16();
            DllCharacteristics = bs.ReadUInt16();
            SizeOfStackReserve = bs.ReadUInt64();
            SizeOfStackCommit = bs.ReadUInt64();
            SizeOfHeapReserve = bs.ReadUInt64();
            SizeOfHeapCommit = bs.ReadUInt64();
            LoaderFlags = bs.ReadUInt32();
            NumberOfRvaAndSizes = bs.ReadUInt32();
            for (int i = 0; i < 16; i++)
            {
                var dir = new IMAGE_DATA_DIRECTORY();
                dir.Read(bs);
                DataDirectory[i] = dir;
            }
        }
    }

    public class IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress { get; private set; }
        public uint Size { get; private set; }

        public void Read(BinaryStream bs)
        {
            VirtualAddress = bs.ReadUInt32();
            Size = bs.ReadUInt32();
        }
    }

    /// <summary>
    /// ST
    /// </summary>
    public class StringTable
    {
        public uint TablePointer { get; private set; }
        public uint TableSize { get; private set; }
        public uint Field_0x08 { get; private set; }
        public uint Pointer_0x0C { get; private set; }
        public uint Field_0x10 { get; private set; }
        public uint Field_0x14 { get; private set; }
        public uint Field_0x18 { get; private set; }
        public uint Field_0x1C { get; private set; }
        public uint Field_0x20 { get; private set; }
        public uint Pointer_0x24 { get; private set; }
        public HashTable HT { get; set; } = new();

        public void Read(BinaryStream bs, IMAGE image)
        {
            TablePointer = bs.ReadUInt32() - image.PvBase;
            TableSize = bs.ReadUInt32();
            Field_0x08 = bs.ReadUInt32();
            Pointer_0x0C = bs.ReadUInt32() - image.PvBase;
            Field_0x10 = bs.ReadUInt32();
            Field_0x14 = bs.ReadUInt32();
            Field_0x18 = bs.ReadUInt32();
            Field_0x1C = bs.ReadUInt32();
            Field_0x20 = bs.ReadUInt32();
            Pointer_0x24 = bs.ReadUInt32() - image.PvBase;

            bs.Position = Pointer_0x0C;
            HT.Read(bs, image, this);
        }
    }

    /// <summary>
    /// HT
    /// </summary>
    public class HashTable
    {
        public uint Field_0x00 { get; private set; }
        public uint Field_0x04 { get; private set; }
        public uint TotalHashEntries { get; private set; }
        public uint NumKeyStrings { get; private set; }
        public uint Field_0x10 { get; private set; }
        public uint NumPointersPerPool { get; private set; }
        public uint MaxPoolSize { get; private set; }
        public ushort Flags { get; private set; }
        public byte Field_0x1E { get; private set; }
        public byte Field_0x1F { get; private set; }
        public uint Field_0x20 { get; private set; }
        public uint PoolPointersPointer { get; private set; }

        public Dictionary<string, uint> Entries { get; set; } = [];

        public void Read(BinaryStream bs, IMAGE image, StringTable st)
        {
            Field_0x00 = bs.ReadUInt32();
            Field_0x04 = bs.ReadUInt32();
            TotalHashEntries = bs.ReadUInt32();
            NumKeyStrings = bs.ReadUInt32();
            Field_0x10 = bs.ReadUInt32();
            NumPointersPerPool = bs.ReadUInt32();
            MaxPoolSize = bs.ReadUInt32();
            Flags = bs.ReadUInt16();
            Field_0x1E = bs.Read1Byte();
            Field_0x1F = bs.Read1Byte();
            Field_0x20 = bs.ReadUInt32();
            PoolPointersPointer = bs.ReadUInt32() - image.PvBase;

            uint cnt = TotalHashEntries / MaxPoolSize;
            if (TotalHashEntries % MaxPoolSize > 0)
                cnt++;

            for (int i = 0; i < cnt; i++)
            {
                bs.Position = PoolPointersPointer + (i * 0x04);
                uint poolOffset = bs.ReadUInt32() - image.PvBase;

                uint thisCnt = i != cnt - 1 ? MaxPoolSize : TotalHashEntries % MaxPoolSize;

                for (int j = 0; j < thisCnt; j++)
                {
                    bs.Position = poolOffset + (j * 0x04);

                    uint entriesStartOffset = bs.ReadUInt32();
                    if (entriesStartOffset != 0)
                    {
                        bs.Position = entriesStartOffset - image.PvBase;

                        while (true)
                        {
                            uint entryOffset = bs.ReadUInt32();
                            uint nextKey = bs.ReadUInt32();

                            if (entryOffset != 0)
                            {
                                bs.Position = entryOffset - image.PvBase;

                                // EXTERNAL (size = 0x30)
                                {
                                    uint flags = bs.ReadUInt32();
                                    uint stringOffset = bs.ReadUInt32();
                                    uint field_0x08 = bs.ReadUInt32();
                                    uint field_0x0C = bs.ReadUInt32();
                                    uint pointer_0x10 = bs.ReadUInt32();
                                    ushort field_0x14 = bs.ReadUInt16();
                                    ushort field_0x16 = bs.ReadUInt16();
                                    ushort field_0x18 = bs.ReadUInt16();
                                    bs.Read1Byte();
                                    bs.Read1Byte();
                                    uint relativeExeOffset = bs.ReadUInt32();

                                    bs.Position = st.TablePointer + stringOffset;
                                    string str = bs.ReadString(StringCoding.ZeroTerminated);
                                    Entries.Add(str, relativeExeOffset);
                                }

                            }

                            if (nextKey == 0)
                                break;

                            bs.Position = nextKey - image.PvBase;
                        }
                    }
                }
            }

        }

        // Debug only, used to hash a mangled symbol to get its entry in the hash table
        private (uint poolIndex, uint entryIndex) HashFindEntryLookup(string mangledSymbol)
        {
            uint hash = 0;
            for (int i = 0; i < mangledSymbol.Length; i++)
                hash += 0x40001u * mangledSymbol[i] + (hash ^ (hash >> 1));

            uint v12 = hash % 0x40000003;

            uint test = 0;
            if (Field_0x04 == 4096)
                test = v12 & 0xFFF;
            else
                test = v12 % Field_0x04;

            if (test < Field_0x00)
                test = v12 % (2 * Field_0x04);

            uint poolIndex = 0;
            uint entryIndex = 0;
            if (MaxPoolSize == 4096)
            {
                poolIndex = test >> 12;
                entryIndex = test & 0xFFF;
            }
            else
            {
                poolIndex = test / MaxPoolSize;
                entryIndex = test % MaxPoolSize;
            }

            return (poolIndex, entryIndex);
        }
    }
}
