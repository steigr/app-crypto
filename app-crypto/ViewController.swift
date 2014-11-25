//
//  ViewController.swift
//  app-crypto
//
//  Created by Mathias Kaufmann on 22.11.14.
//  Copyright (c) 2014 Mathias Kaufmann. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.

        var stampCrypto = StampCrypto()
        stampCrypto.makeRequest()
        stampCrypto.registerDeviceAndSignRequest()

        var device = Device()
        
        device.loadResource()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

