<!--
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
-->

# JavaCard Libraries

Local `*.jar` dependencies repository.

You can add here local dependencies if there are not available on the 
Maven central repository or you are not willing to use those.

If there is a `test.jar` file you can add it as a dependency
by adding the following line to the `dependencies {}` block.

```gradle
compile name: 'test'
```

This works only for JAR files placed right in the `/libs` directory (flat hierarchy).
The artifact group is ignored, artifact is searched just by the name.
 
For subdirectories you have to use the `files()` or `fileTree` as demonstrated below.

Java 8+ is required.

## Custom JCardSim

If you want to use custom JCardSim version place your jar in the `libs` directory, e.g., as
`libs/jcardsim-3.0.6.jar`

Then modify project gradle file `build.gradle`, in particular section `dependencies` as follows:

```gradle
dependencies {
    testCompile 'org.testng:testng:6.1.1'
    testCompile group: 'com.klinec', name: 'javacard-tools', version: '0.0.1', transitive: false
    
    // Previously, the jcardsim record:
    // jcardsim 'com.licel:jcardsim:3.0.5'
            
    // Now using custom version.
    jcardsim ':jcardsim:3.0.6'
        
    // Or you can include jcardsim directly:
    // jcardsim files(libs + '/jcardsim-3.0.5.jar')
}

```


## `globalplatform-2_1_1`

Globalplatform libraries

```gradle
compile fileTree(dir: rootDir.absolutePath + '/libs/globalplatform-2_1_1', include: '*.jar')
```

Or if you use predefined gradle file with `libs` variable:

```gradle
compile fileTree(dir: libs + '/globalplatform-2_1_1', include: '*.jar')
```

License: no idea

## `visa_openplatform`

```gradle
compile fileTree(dir: rootDir.absolutePath + '/libs/visa_openplatform-2_0', include: '*.jar')
```

License: no idea

