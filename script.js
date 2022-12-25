'use strict';

//Memory dumping script based on fridump and https://github.com/azurda/frida-dump

function storeArrayBuffer(filename, buffer) {
    var destFileName = new File(filename, "wb");
    destFileName.write(buffer);
    destFileName.flush();
    destFileName.close();
}

rpc.exports = {
    enumerateRanges: function (prot) {
        return Process.enumerateRangesSync({protection: prot, coalesce: true});
    },

    enumerateModules: function () {
        return Process.enumerateModules();
    },

    getMainModule: function() {
        // Find the module for the program itself, always at index 0:
        const m = Process.enumerateModules()[0];

        // Print its properties:
        console.log(JSON.stringify(m));

        // Dump it from its base address:
        console.log(hexdump(m.base));
    },

    readMemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
    },

    //Broken, doesn't return memory data (but has it locally)
    dumpProcessMemory: function(memoryProt) {
        var ranges = Process.enumerateRanges({protection: memoryProt, coalesce: true});
        var totalRanges = ranges.length;
        var failedDumps = 0;
        var rangeNames = [];
        var out_ranges = [];
        console.log("Located " + totalRanges + " memory ranges matching [" + memoryProt + "]");
        ranges.forEach(function (range) {
            console.log("Dumping range " + range.base);
            var arrayBuf = null;
            try {
                arrayBuf = range.base.readByteArray(range.size);
                console.log(range.size + " : " + arrayBuf.length);
            } catch (e) {
                failedDumps += 1;
                console.log("fail: " + e);
                return;
            }

            if (arrayBuf) {
                /* //Local dumping - doesn't work because of permissions
                try {
                    var dumpPath = "dumps/" + range.base;
                    console.log("Saving dump: " + dumpPath);
                    storeArrayBuffer(dumpPath, arrayBuf);
                }
                catch (e)
                {
                    console.log("Local saving failed: " + e);
                }
                */

                rangeNames.push(range.base);
                out_ranges.push(arrayBuf);
            }
        });
        var sucessfulDumps = totalRanges - failedDumps;
        console.log("Succesfully collected " + sucessfulDumps + "/" + totalRanges + " ranges.");
        return [rangeNames, out_ranges]; //TODO: doesn't return the proper memory data. why?
    }
}; 
