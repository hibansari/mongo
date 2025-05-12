package com.example.analyzer;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.body.Parameter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

public class JavaStaticAnalyzer {
    static int totalClasses = 0;
    static int totalMethods = 0;
    static int totalCalls = 0;

    static Map<String, List<String>> classDependencies = new HashMap<>();
    private static final Set<String> declaredMethods = new HashSet<>();
    static Map<String, List<String>> methodCalls = new HashMap<>();
    static Set<String> usedMethods = new HashSet<>();
    static Map<String, List<String>> declaredMethodsByClass = new HashMap<>();
    static Set<String> declaredClasses = new HashSet<>();
    static Set<String> usedClasses = new HashSet<>();
    
    // Common Java built-in types and packages to filter out
    private static final Set<String> BUILTIN_TYPES = Set.of(
        "int", "long", "double", "float", "boolean", "byte", "short", "char", "void",
        "String", "Object", "Enum", "Exception", "RuntimeException", "Throwable",
        "List", "Map", "Set", "HashMap", "HashSet", "ArrayList", "LinkedList",
        "Collection", "Iterator", "Iterable", "Optional", "Stream"
    );
    
    private static final Set<String> BUILTIN_PACKAGES = Set.of(
        "java.lang", "java.util", "java.io", "java.nio", "java.time", "java.math",
        "java.text", "java.net", "java.security", "java.sql", "javax.persistence",
        "javax.transaction", "javax.validation", "javax.ws.rs", "javax.inject",
        "javax.enterprise", "javax.servlet", "javax.ejb"
    );
    
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.out.println("Usage: java JavaStaticAnalyzer <path-to-java-src>");
            return;
        }
    
        // Check valid filepath
        File root = new File(args[0]);
        if (!root.exists() || !root.isDirectory()) {
            System.out.println("Invalid source directory: " + args[0]);
            return;
        }
    
        // Ensure the report directory exists
        File reportDir = new File("report");
        if (!reportDir.exists()) {
            boolean created = reportDir.mkdirs();
            if (!created) {
                System.err.println("Failed to create report directory.");
                return;
            }
        }
    
        List<File> javaFiles = collectJavaFiles(root);
    
        for (File file : javaFiles) {
            parseJavaFile(file);
        }
    
        // Export results to DOT and JSON in report directory
        exportToDot(methodCalls, new File(reportDir, "method_hierarchy.dot"));
        exportToJson(methodCalls, new File(reportDir, "method_graph.json"));
        copyGraphHtmlToReport(); // Make sure this writes to 'report/' as well
    
        writeSummaryReport(); // Likewise, ensure it targets 'report/' if it writes files
    
        // Start interactive CLI
        startInteractiveCLI();
    }
    

    private static List<File> collectJavaFiles(File dir) {
        List<File> fileList = new ArrayList<>();
        for (File file : Objects.requireNonNull(dir.listFiles())) {
            if (file.isDirectory()) {
                fileList.addAll(collectJavaFiles(file));  // Recurse into subdirectories
            } else if (file.getName().endsWith(".java")) {
                fileList.add(file);  // Add Java files to the list
            }
        }
        return fileList;  // Return the list of Java files
    }

    private static void parseJavaFile(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            CompilationUnit cu = StaticJavaParser.parse(in);
            System.out.println("\n--- Analyzing: " + file.getPath() + " ---");
    
            // Set of all declared class names in the file
            List<String> classesInFile = new ArrayList<>();
            cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
                String className = cls.getNameAsString();
                declaredClasses.add(className);
                classesInFile.add(className);
                System.out.println("Class: " + className);
            });
    
            // Extract imports and determine dependencies
            Set<String> dependencies = new HashSet<>();
            cu.getImports().forEach(imp -> {
                String importName = imp.getNameAsString();
                
                // Skip static imports
                if (imp.isStatic()) {
                    return;
                }
                
                // Extract class name from import
                String[] parts = importName.split("\\.");
                if (parts.length > 0) {
                    String importedClass = parts[parts.length - 1];
                    
                    // Skip wildcard imports and builtin packages
                    if (!importedClass.equals("*") && !isBuiltinPackage(importName)) {
                        dependencies.add(importedClass);
                    }
                }
                System.out.println("Import: " + importName);
            });
    
            // Add dependencies for each class in this file
            for (String className : classesInFile) {
                classDependencies.computeIfAbsent(className, k -> new ArrayList<>())
                    .addAll(dependencies);
            }
    
            // Instantiate a new visitor for each file
            MethodHierarchyVisitor visitor = new MethodHierarchyVisitor();
            cu.accept(visitor, null);
    
            // Collect and merge data from this file
            methodCalls.putAll(visitor.methodCalls);
            usedMethods.addAll(visitor.usedMethods);
            usedClasses.addAll(visitor.usedClasses);
            
            // Add dependencies from method calls and field types
            for (String className : classesInFile) {
                List<String> classDeps = classDependencies.computeIfAbsent(className, k -> new ArrayList<>());
                classDeps.addAll(visitor.getClassDependencies());
            }
    
            // Print method call hierarchies
            System.out.println("Method Call Hierarchies:");
            visitor.methodCalls.forEach((caller, callees) -> {
                System.out.println("Method: " + caller);
                for (String callee : callees) {
                    System.out.println("  calls -> " + callee);
                }
            });
    
            int classCount = cu.findAll(ClassOrInterfaceDeclaration.class).size();
            int methodCount = cu.findAll(MethodDeclaration.class).size();
            int callCount = cu.findAll(MethodCallExpr.class).size();
    
            totalClasses += classCount;
            totalMethods += methodCount;
            totalCalls += callCount;
    
        } catch (Exception e) {
            System.err.println("Error parsing " + file.getPath() + ": " + e.getMessage());
        }
    }
    

    public static class MethodHierarchyVisitor extends VoidVisitorAdapter<String> {

        Map<String, List<String>> methodCalls = new HashMap<>();
        Set<String> usedMethods = new HashSet<>();
        Set<String> usedClasses = new HashSet<>();
        private Map<String, String> methodReturnTypes = new HashMap<>();
        private Set<String> classDependencies = new HashSet<>();
    
        private Map<String, String> fieldTypes = new HashMap<>();
        private Map<String, String> localTypes = new HashMap<>();
    
        private String currentClass = "";
        private String currentMethod = "";
    
        @Override
        public void visit(ClassOrInterfaceDeclaration cid, String arg) {
            currentClass = cid.getNameAsString();
            
            // Skip annotations when visiting class-level annotations
            // This prevents annotation types from being treated as dependencies
            super.visit(cid, arg);
        }
    
        
        @Override
        public void visit(FieldDeclaration fd, String className) {
            for (VariableDeclarator var : fd.getVariables()) {
                String varName = var.getNameAsString();
                String varType = extractBaseType(var.getType().asString());
                fieldTypes.put(varName, varType);
                
                // Mark the type as used
                markClassAsUsed(varType);
                
                // Add field type as a dependency if it's not a builtin type
                if (!isBuiltinType(varType)) {
                    classDependencies.add(varType);
                }
            }
            super.visit(fd, className);
        }
        
        @Override
        public void visit(MethodDeclaration md, String className) {
            currentMethod = md.getNameAsString();
            localTypes.clear();
            
            // Add declared method to the global set
            String qualifiedMethodName = className + "_" + md.getNameAsString();
            declaredMethods.add(qualifiedMethodName);
            
            // Also add to class-specific list
            declaredMethodsByClass.computeIfAbsent(className, k -> new ArrayList<>()).add(qualifiedMethodName);
            
            // Process parameters
            for (Parameter param : md.getParameters()) {
                String paramName = param.getNameAsString();
                String paramType = extractBaseType(param.getType().asString());
                localTypes.put(paramName, paramType);
                
                // Mark parameter type as used
                markClassAsUsed(paramType);
                
                // Add parameter type as a dependency if it's not builtin
                if (!isBuiltinType(paramType)) {
                    classDependencies.add(paramType);
                }
            }
            
            String returnType = extractBaseType(md.getType().asString());
            methodReturnTypes.put(qualifiedMethodName, returnType);
            
            // Mark return type as used
            markClassAsUsed(returnType);
            
            // Add return type as a dependency if it's not builtin
            if (!isBuiltinType(returnType)) {
                classDependencies.add(returnType);
            }
            
            super.visit(md, className);
        }
        
        @Override
        public void visit(VariableDeclarationExpr vde, String arg) {
            for (VariableDeclarator var : vde.getVariables()) {
                String varName = var.getNameAsString();
                String varType = extractBaseType(var.getType().asString());
                localTypes.put(varName, varType);
                
                // Mark variable type as used
                markClassAsUsed(varType);
                
                // Add local variable type as a dependency if it's not builtin
                if (!isBuiltinType(varType)) {
                    classDependencies.add(varType);
                }
            }
            super.visit(vde, arg);
        }
        
        @Override
        public void visit(MethodCallExpr mce, String className) {
            String callerMethod = currentClass + "_" + currentMethod;
            String callee;
            
            if (mce.getScope().isPresent()) {
                Expression scopeExpr = mce.getScope().get();
                String type;
                
                if (scopeExpr.isNameExpr()) {
                    String scopeName = scopeExpr.asNameExpr().getNameAsString();
                    type = localTypes.getOrDefault(scopeName,
                    fieldTypes.getOrDefault(scopeName, "Unknown"));
                    
                } else if (scopeExpr.isMethodCallExpr()) {
                    MethodCallExpr innerCall = scopeExpr.asMethodCallExpr();
                    String innerReturnType = resolveReturnTypeFromCall(innerCall);
                    type = innerReturnType != null ? innerReturnType : "Unknown";
                } else {
                    type = "Unknown";
                }
                
                callee = type + "_" + mce.getNameAsString();
                usedClasses.add(type);
                
                // Add called class as a dependency if it's not builtin and not Unknown
                if (!isBuiltinType(type) && !type.equals("Unknown")) {
                    classDependencies.add(type);
                }
                
            } else {
                callee = currentClass + "_" + mce.getNameAsString();
            }
            
            methodCalls.computeIfAbsent(callerMethod, k -> new ArrayList<>()).add(callee);
            usedMethods.add(callee);
            
            // Debug print (optional)
            System.out.println("Call: " + callerMethod + " -> " + callee);
            
            super.visit(mce, className);
        }
        
        // Add this method to track class usage more comprehensively
        private void markClassAsUsed(String className) {
            if (!isBuiltinType(className) && !className.equals("Unknown")) {
                usedClasses.add(className);
            }
        }
        
        private boolean isBuiltinType(String type) {
            // Check if it's a primitive or common Java type
            if (BUILTIN_TYPES.contains(type)) {
                return true;
            }
            
            // Check if it starts with java. or javax.
            return type.startsWith("java.") || type.startsWith("javax.");
        }

        
        
        public Set<String> getClassDependencies() {
            // Filter out built-in types, primitives, and unknown
            return classDependencies.stream()
                .filter(dep -> !isBuiltinType(dep) && !dep.equals("Unknown"))
                .collect(HashSet::new, HashSet::add, HashSet::addAll);
        }
    
        private String resolveReturnTypeFromCall(MethodCallExpr call) {
            String methodName = call.getNameAsString();
    
            // If the method itself is scoped (e.g., obj.getSomething().getOther()), resolve recursively
            if (call.getScope().isPresent()) {
                Expression scope = call.getScope().get();
                if (scope.isMethodCallExpr()) {
                    String innerReturnType = resolveReturnTypeFromCall(scope.asMethodCallExpr());
                    return resolveReturnType(innerReturnType + "_" + methodName);
                } else if (scope.isNameExpr()) {
                    String scopeName = scope.asNameExpr().getNameAsString();
                    String scopeType = localTypes.getOrDefault(scopeName,
                            fieldTypes.getOrDefault(scopeName, "Unknown"));
                    return resolveReturnType(scopeType + "_" + methodName);
                }
            }
    
            // Fallback to unqualified search
            return resolveReturnType(methodName);
        }
    
        private String resolveReturnType(String fullMethodName) {
            if (methodReturnTypes.containsKey(fullMethodName)) {
                return methodReturnTypes.get(fullMethodName);
            }
    
            // Fallback: look for any method ending with _methodName
            for (String key : methodReturnTypes.keySet()) {
                if (key.endsWith("_" + fullMethodName)) {
                    return methodReturnTypes.get(key);
                }
            }
    
            return "Unknown";
        }
    }

    private static boolean isBuiltinPackage(String fullyQualifiedName) {
        return BUILTIN_PACKAGES.stream().anyMatch(pkg -> fullyQualifiedName.startsWith(pkg + "."));
    }
    
    private static String extractBaseType(String typeString) {
        // Remove generics (e.g., List<String> -> List)
        if (typeString.contains("<")) {
            typeString = typeString.substring(0, typeString.indexOf("<"));
        }
        
        // Remove array notation (e.g., String[] -> String)
        if (typeString.contains("[")) {
            typeString = typeString.substring(0, typeString.indexOf("["));
        }
        
        return typeString.trim();
    }
    

    

    private static void writeSummaryReport() {
        try {
            File file = new File(ensureReportFolder(), "analysis_report.txt");
            List<String> lines = List.of(
                "=== Java Project Static Analysis Report ===",
                "Total Classes: " + totalClasses,
                "Total Methods: " + totalMethods,
                "Total Method Calls: " + totalCalls,
                "DOT Graph: method_hierarchy.dot",
                "Interactive Graph: graph.html (uses method_graph.json)"
            );
            java.nio.file.Files.write(file.toPath(), lines);
            System.out.println("Wrote structured summary: report/analysis_report.txt");
        } catch (IOException e) {
            System.err.println("Error writing summary report: " + e.getMessage());
        }
    }

    private static File ensureReportFolder() {
        File folder = new File("report");
        if (!folder.exists()) folder.mkdir();
        return folder;
    }

    private static void exportToDot(Map<String, List<String>> methodCalls, File outputFile) {
        try (PrintWriter writer = new PrintWriter(outputFile)) {
            writer.println("digraph MethodCalls {");
            writer.println("  rankdir=LR;");
            writer.println("  node [shape=box];");

            Set<String> allNodes = new HashSet<>();

            // Write edges
            for (Map.Entry<String, List<String>> entry : methodCalls.entrySet()) {
                String caller = entry.getKey();
                allNodes.add(caller);
                for (String callee : entry.getValue()) {
                    writer.printf("  \"%s\" -> \"%s\";%n", caller, callee);
                    allNodes.add(callee);
                }
            }

            // Add standalone unused nodes (unused but declared methods/classes)
            Set<String> allUsed = new HashSet<>(usedMethods);
            Set<String> unused = new HashSet<>(declaredMethods);
            unused.removeAll(allUsed);

            for (String unusedMethod : unused) {
                if (!allNodes.contains(unusedMethod)) {
                    writer.printf("  \"%s\";%n", unusedMethod);
                }
            }

            writer.println("}");
        } catch (IOException e) {
            System.err.println("Error writing DOT file: " + e.getMessage());
        }
    }

    
    private static void exportToJson(Map<String, List<String>> methodCalls, File outputFile) {
        try (PrintWriter writer = new PrintWriter(outputFile)) {
            writer.println("{");
            writer.println("  \"nodes\": [");
    
            Set<String> allNodes = new HashSet<>();
            for (String caller : methodCalls.keySet()) {
                allNodes.add(caller);
                allNodes.addAll(methodCalls.get(caller));
            }
    
            Set<String> unused = new HashSet<>(declaredMethods);
            unused.removeAll(usedMethods);
            allNodes.addAll(unused);  // include unused methods
    
            int count = 0;
            for (String node : allNodes) {
                writer.printf("    {\"id\": \"%s\"}%s%n", node, (++count < allNodes.size()) ? "," : "");
            }
    
            writer.println("  ],");
            writer.println("  \"links\": [");
    
            List<String> edges = new ArrayList<>();
            for (Map.Entry<String, List<String>> entry : methodCalls.entrySet()) {
                String caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    edges.add(String.format("    {\"source\": \"%s\", \"target\": \"%s\"}", caller, callee));
                }
            }
    
            for (int i = 0; i < edges.size(); i++) {
                writer.print(edges.get(i));
                if (i < edges.size() - 1) writer.println(",");
                else writer.println();
            }
    
            writer.println("  ]");
            writer.println("}");
        } catch (IOException e) {
            System.err.println("Error writing JSON file: " + e.getMessage());
        }
    }
    
    
    private static void copyGraphHtmlToReport() {
        try {
            File source = new File("graph.html");
            File destination = new File(ensureReportFolder(), "graph.html");
            java.nio.file.Files.copy(
                source.toPath(),
                destination.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            );
            System.out.println("Copied graph.html to report/graph.html");
        } catch (IOException e) {
            System.err.println("Error copying graph.html: " + e.getMessage());
        }
    }

    public static List<String> findDependenciesForClass(String className) {
        List<String> deps = classDependencies.getOrDefault(className, new ArrayList<>());
        // Remove duplicates and return
        return new ArrayList<>(new HashSet<>(deps));
    }

    public static void identifyUnused() {
        // Unused classes
        System.out.println("\n=== Unused Classes ===");
        for (String cls : declaredClasses) {
            if (!usedClasses.contains(cls)) {
                System.out.println("Unused class: " + cls);
            }
        }
    
        // Unused methods grouped by class
        System.out.println("\n=== Unused Methods by Class ===");
        for (var entry : declaredMethodsByClass.entrySet()) {
            String className = entry.getKey();
            List<String> methodList = entry.getValue();
    
            List<String> unusedInClass = new ArrayList<>();
            for (String method : methodList) {
                // Extract method name without class prefix
                String methodName = method.substring(method.lastIndexOf('_') + 1);
                
                // Skip main method and common framework methods
                if (isSpecialMethod(methodName)) {
                    continue;
                }
                
                if (!usedMethods.contains(method)) {
                    unusedInClass.add(method);
                }
            }
    
            if (!unusedInClass.isEmpty()) {
                System.out.println("Class: " + className);
                unusedInClass.forEach(m -> System.out.println("  - " + m));
            }
        }
    }
    
    private static boolean isSpecialMethod(String methodName) {
        // Common methods that might not be called internally but are used by frameworks
        Set<String> specialMethods = Set.of(
            "main",           // Entry point
            "toString",       // Object method
            "equals",         // Object method
            "hashCode",       // Object method
            "finalize",       // Object method
            "clone",          // Object method
            "getClass",       // Object method
            "wait",           // Object method
            "notify",         // Object method
            "notifyAll"       // Object method
        );
        
        return specialMethods.contains(methodName);
    }
    

    public static Set<String> findImpactRadius(String classNameOrMethod) {
        Set<String> impactedMethods = new HashSet<>();
        methodCalls.forEach((caller, callees) -> {
            if (callees.contains(classNameOrMethod)) {
                impactedMethods.add(caller);
            }
        });
        return impactedMethods;
    }

    private static void listAllClasses() {
        System.out.println("\n=== Declared Classes ===");
        for (String cls : declaredClasses) {
            System.out.println(" - " + cls);
        }
    }
    

    public static void startInteractiveCLI() {
        Scanner scanner = new Scanner(System.in);
        String command;

        System.out.println("Java Static Analyzer Interactive CLI");
        System.out.println("Type 'exit' to quit.");

        while (true) {
            System.out.print("> ");
            command = scanner.nextLine();

            if (command.equalsIgnoreCase("exit")) {
                break;
            }

            String[] parts = command.split(" ", 2);
            String queryType = parts[0];

            switch (queryType.toLowerCase()) {
                case "dependencies":
                    if (parts.length == 2) {
                        List<String> dependencies = findDependenciesForClass(parts[1]);
                        System.out.println("Dependencies for " + parts[1] + ": " + dependencies);
                    } else {
                        System.out.println("Usage: dependencies <class_name>");
                    }
                    break;
                case "unused":
                    identifyUnused();
                    break;
                case "impact":
                    if (parts.length == 2) {
                        Set<String> impacted = findImpactRadius(parts[1]);
                        System.out.println("Impact radius for " + parts[1] + ": " + impacted);
                    } else {
                        System.out.println("Usage: impact <class_or_method>");
                    }
                    break;
                case "class":
                    listAllClasses();
                    break;
                default:
                    System.out.println("Unknown command. Available commands: dependencies, unused, impact, exit.");
            }
        }
        scanner.close();
    }
}