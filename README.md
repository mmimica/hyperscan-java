# hyperscan-java
[![Maven Central](https://img.shields.io/maven-central/v/com.gliwka.hyperscan/hyperscan.svg?label=Maven%20Central)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.gliwka.hyperscan%22%20a%3A%22hyperscan%22)
![example workflow name](https://github.com/gliwka/hyperscan-java/workflows/Java%20CI/badge.svg)



[hyperscan](https://github.com/intel/hyperscan) is a high-performance multiple regex matching library.

It uses hybrid automata techniques to allow simultaneous matching of large numbers (up to tens of thousands) of regular expressions and for the matching of regular expressions across streams of data.


This project is a third-party developed JNA based java wrapper for the [hyperscan](https://github.com/intel/hyperscan) project to enable developers to integrate hyperscan in their java (JVM) based projects.

## Add it to your project
This project is available on maven central.

#### Maven
```xml
<dependency>
    <groupId>com.gliwka.hyperscan</groupId>
    <artifactId>hyperscan</artifactId>
    <version>1.0.0</version>
</dependency>
```

#### Gradle

```gradle
compile group: 'com.gliwka.hyperscan', name: 'hyperscan', version: '1.0.0'
```

#### sbt
```sbt
libraryDependencies += "com.gliwka.hyperscan" %% "hyperscan" % "1.0.0"
```

## Simple example
```java
import com.gliwka.hyperscan.wrapper;

...

//we define a list containing all of our expressions
LinkedList<Expression> expressions = new LinkedList<Expression>();

//the first argument in the constructor is the regular pattern, the latter one is a expression flag
//make sure you read the original hyperscan documentation to learn more about flags
//or browse the ExpressionFlag.java in this repo.
expressions.add(new Expression("[0-9]{5}", EnumSet.of(ExpressionFlag.SOM_LEFTMOST)));
expressions.add(new Expression("Test", ExpressionFlag.CASELESS));


//we precompile the expression into a database.
//you can compile single expression instances or lists of expressions

//since we're interacting with native handles always use try-with-resources or call the close method after use
try(Database db = Database.compile(expressions)) {
    //initialize scanner - one scanner per thread!
    //same here, always use try-with-resources or call the close method after use
    try(Scanner scanner = new Scanner())
    {
        //allocate scratch space matching the passed database
        scanner.allocScratch(db);


        //provide the database and the input string
        //returns a list with matches
        //synchronized method, only one execution at a time (use more scanner instances for multithreading)
        List<Match> matches = scanner.scan(db, "12345 test string");

        //matches always contain the expression causing the match and the end position of the match
        //the start position and the matches string it self is only part of a matach if the
        //SOM_LEFTMOST is set (for more details refer to the original hyperscan documentation)
    }

    // Save the database to the file system for later use
    try(OutputStream out = new FileOutputStream("db")) {
        db.save(out);
    }

    // Later, load the database back in. This is useful for large databases that take a long time to compile.
    // You can compile them offline, save them to a file, and then quickly load them in at runtime.
    // The load has to happen on the same type of platform as the save.
    try (InputStream in = new FileInputStream("db");
         Database loadedDb = Database.load(in)) {
        // Use the loadedDb as before.
    }
}
catch (CompileErrorException ce) {
    //gets thrown during  compile in case something with the expression is wrong
    //you can retrieve the expression causing the exception like this:
    Expression failedExpression = ce.getFailedExpression();
}
catch(IOException ie) {
  //IO during serializing / deserializing failed
}
```


## Limitations of hyperscan-java

hyperscan only supports a subset of regular expressions. Notable exceptions are for example backreferences and capture groups. Please read the [hyperscan developer reference](https://intel.github.io/hyperscan/dev-reference/) so you get a good unterstanding how hyperscan works and what the limitations are.

## Native libraries
This wrapper ships with pre-compiled hyperscan binaries for windows, linux (glibc >=2.12) and osx for x86_64 CPUs.
You can find the repository with the native libraries [here](https://github.com/gliwka/hyperscan-java-native)

## Documentation
The [hyperscan developer reference](https://intel.github.io/hyperscan/dev-reference/) explains hyperscan.
The javadoc is located [here](https://gliwka.github.io/hyperscan-java/).


## Contributing
 Feel free to raise issues or submit a pull request.

## Credits
Shoutout to [@eliaslevy](https://github.com/eliaslevy), [@krzysztofzienkiewicz](https://github.com/krzysztofzienkiewicz) and [@swapnilnawale](https://github.com/swapnilnawale) for all the great contributions.

Thanks to Intel for opensourcing hyperscan!

## License
[BSD 3-Clause License](LICENSE)

