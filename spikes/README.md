# Phase 0 spikes — THROWAWAY

Code here answers the questions in spec section 11. It is never imported by product code and
will not be maintained. What each spike asked, and its fallback, is spec section 11.

Build:
    cd spikes
    go build -buildmode=c-archive -o build/libspikecore.a ./s11-bridge/core
    swift build --package-path swift -Xlinker -L"$PWD/build"
