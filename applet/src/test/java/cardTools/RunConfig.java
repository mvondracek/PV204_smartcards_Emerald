/*
This file was merged and modified based on "JavaCard Template project with
Gradle" which was published under MIT license included below.
https://github.com/crocs-muni/javacard-gradle-template-edu

License from 2020-04-18 https://github.com/crocs-muni/javacard-gradle-template-edu/blob/ebcb012a192092678eb9b7f198be5a6a26136f31/LICENSE
~~~
The MIT License (MIT)

Copyright (c) 2015 Dusan Klinec, Martin Paljak, Petr Svenda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
~~~
*/

package cardTools;

/**
 * Applet run configuration.
 *
 * @author Petr Svenda, Dusan Klinec
 */
public class RunConfig {
    int targetReaderIndex = 0;
    public int numRepeats = 1;
    public Class appletToSimulate;
    boolean bReuploadApplet = false;
    byte[] installData = null;
    
    public enum CARD_TYPE {
        PHYSICAL, JCOPSIM, JCARDSIMLOCAL, JCARDSIMREMOTE
    }

    public CARD_TYPE testCardType = CARD_TYPE.PHYSICAL;
    
    public static RunConfig getDefaultConfig() {
        RunConfig runCfg = new RunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.testCardType = CARD_TYPE.PHYSICAL;
        runCfg.appletToSimulate = null;
        
        return runCfg;
    }

    public int getTargetReaderIndex() {
        return targetReaderIndex;
    }

    public int getNumRepeats() {
        return numRepeats;
    }

    public Class getAppletToSimulate() {
        return appletToSimulate;
    }

    public boolean isbReuploadApplet() {
        return bReuploadApplet;
    }

    public byte[] getInstallData() {
        return installData;
    }

    public CARD_TYPE getTestCardType() {
        return testCardType;
    }

    public RunConfig setTargetReaderIndex(int targetReaderIndex) {
        this.targetReaderIndex = targetReaderIndex;
        return this;
    }

    public RunConfig setNumRepeats(int numRepeats) {
        this.numRepeats = numRepeats;
        return this;
    }

    public RunConfig setAppletToSimulate(Class appletToSimulate) {
        this.appletToSimulate = appletToSimulate;
        return this;
    }

    public RunConfig setbReuploadApplet(boolean bReuploadApplet) {
        this.bReuploadApplet = bReuploadApplet;
        return this;
    }

    public RunConfig setInstallData(byte[] installData) {
        this.installData = installData;
        return this;
    }

    public RunConfig setTestCardType(CARD_TYPE testCardType) {
        this.testCardType = testCardType;
        return this;
    }
}
