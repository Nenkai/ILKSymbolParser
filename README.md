# ILKSymbolParser

This will only work with 32bit .ilk files from MSVC linker version 14.0.24125. The format is undocumented and changes very frequently.

010 Editor template [here](https://github.com/Nenkai/010GameTemplates/blob/main/Microsoft/MS_ilk_14.0.24215_32bit.bt)

---

This project was only made to work against a certain game I had to extract information from. It will need adjusting to support any other version (or 64 bit).

If you wish to reverse it for another version, you may need to reverse MSVC's `link.exe`, make sure to use the matching linker version. Use Detect-It-Easy or something.
