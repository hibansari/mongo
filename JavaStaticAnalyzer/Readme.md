# Java Static Analyzer

This project is a Java static analyzer that parses Java source code using [JavaParser](https://javaparser.org/) to extract:

- Method call hierarchies
- Class dependencies
- Field declarations
- Unused methods (optional)
- Outputs a graph in JSON format for visualization which can be rendered using the graph.html file 
- Outputs a .dot file that can be visualised using graphviz (https://edotor.net/)

# How to Run

## Prerequisites

- Java 11+
- Maven (for dependency management)

## Steps

1. Clone the repo
```bash
git clone https://github.com/hibansari/mongo.git
cd JavaStaticAnalyzer 
```

2. Compile the project and execute
```bash
mvn compile
mvn exec:java -Dexec.args=path-to-src-project-that-needs-to-be-analyzed
```

3. This will produce a new folder (report/) which contains the following files:
- analysis_report.txt
- graph.html
- method_graph.json
- method_hierarchy.dot

4. Visualising the interactive graph:
- On another terminal, run
```bash
python3 -m http.server 8000
```
- On the browser, open the page: http://localhost:8000/graph.html

5. Visualising the hierarchical view:
- visit: https://edotor.net/
- copy and paste the contents of method_hierarchy.dot 

6. Run Query commands
```bash
dependencies <class>            # show all class dependencies
unused                          # identify unused classes/methods
impact <class_or_method>        # determine the impact radius if a particular component changes
class                           # display all classes
```