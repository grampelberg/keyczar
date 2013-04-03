This is a fork of [keyczar](https://code.google.com/p/keyczar/). I will try and keep it up to date with the latest on google code.

# Clojure

```clojure
(defproject myproject "0.1.0-SNAPSHOT"
  :dependencies [[org.keyczar/keyczar "0.71f.1"]]
  :repositories [["keyczar" "https://raw.github.com/pyronicide/keyczar/mvn-repo/"]]
)
```

# Java

```xml
<repositories>
    <repository>
        <id>keyczar-mvn-repo</id>
        <url>https://raw.github.com/pyronicide/keyczar/mvn-repo/</url>
        <snapshots>
            <enabled>true</enabled>
            <updatePolicy>always</updatePolicy>
        </snapshots>
    </repository>
</repositories>
```
