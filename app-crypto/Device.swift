//
//  Device.swift
//  
//
//  Created by Mathias Kaufmann on 25.11.14.
//
//

import Foundation

class Device: RLMObject {
    dynamic var id = ""
    dynamic var private_key = ""
    dynamic var certificate = ""
    dynamic var certificate_chain = ""
    dynamic var created_at = NSDate(timeIntervalSinceNow: 1)
    dynamic var updated_at = NSDate(timeIntervalSince1970: 1)
    dynamic var transaction_pin = NSInteger(0)
    
    var resource_part = "/devices"
    
    func loadResource() {
        NSLog("Loading Resource")
    }
}