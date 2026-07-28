# Osprey

**Native host situational awareness and attack surface mapper**  
Pure C + COM. Designed to see what Seatbelt and most other tools miss.

## Philosophy

Same approach as Kestrel: use only native Windows interfaces.  
No .NET, no PowerShell, no managed runtime.  
Traffic and API usage should look like ordinary system activity.

## Breakthrough modules (the real differentiators)

| Module        | What it does                                      | Why it is better than Seatbelt                  |
|---------------|---------------------------------------------------|-------------------------------------------------|
| `com`         | Full ROT + interesting CLSIDs + AppID permissions | Seatbelt is almost completely blind to live COM |
| `tokenhunt`   | Cross-process token collection & analysis         | Goes far beyond current-process token           |
| `wmipersist`  | Deep permanent WMI event subscriptions            | Extracts real payloads and bindings             |
| `isolation`   | Real status of Cred Guard / VBS / PPL / WDAC      | Not just registry flags                         |

## Project layout

```
Osprey/
├── include/
│   ├── osprey.h          # core types, output, module system
│   ├── com.h             # COM lifetime + ROT helpers
│   ├── wmi.h             # lightweight WMI session
│   └── modules.h         # module declarations + table
├── src/
│   ├── main.c
│   ├── com.c
│   ├── wmi.c
│   ├── output.c
│   ├── modules/
│   │   ├── com_surface.c     # breakthrough
│   │   ├── token_hunt.c      # breakthrough
│   │   ├── wmi_persist.c     # breakthrough
│   │   ├── isolation.c       # breakthrough
│   │   └── stubs.c           # temporary stubs for classic modules
│   └── util/                 # (future helpers)
└── docs/
```

## Build (Visual Studio)

- Create an empty Console project (x64)
- Add all `.c` files from `src/` and `src/modules/`
- Add `include/` to Additional Include Directories
- Link: `ole32.lib oleaut32.lib wbemuuid.lib advapi32.lib`
- Runtime Library: `/MT` (static, no CRT DLL dependency)
- Character Set: Unicode
- C Language Standard: C11 or C17

## Current status

Skeleton is ready. Breakthrough modules have real (though incomplete) implementations for ROT and WMI persistence.  
Next concrete steps:

1. Finish `Module_ComSurface` (interesting CLSIDs + AppID SD)
2. Implement proper token collection in `Module_TokenHunt`
3. Add process protection level enumeration in `Module_Isolation`
4. Replace stubs with real classic modules one by one

## Author

Built in the same spirit as Kestrel – native, precise, low-noise.
