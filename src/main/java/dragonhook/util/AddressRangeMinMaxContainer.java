package dragonhook.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

public class AddressRangeMinMaxContainer {

    Address minaddr, maxaddr;
    CodeUnit minCU,maxCU;
    //Constructor
    public AddressRangeMinMaxContainer(Address minaddr, Address maxaddr,CodeUnit minCU, CodeUnit maxCU) {
        this.minaddr = minaddr;
        this.maxaddr = maxaddr;
        this.minCU = minCU;
        this.maxCU = maxCU;
    }


}
