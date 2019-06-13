/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2019 Nima Yahyazadeh. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.golang.GoModDependency;
import org.owasp.dependencycheck.data.golang.GoModJsonParser;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Go lang dependency analyzer.
 *
 * @author Matthijs van den Bos
 */
@ThreadSafe
@Experimental
public class GolangModAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The List of ComposerDependencies found
     */
    private final List<GoModDependency> goModDependencies = new ArrayList<>();

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GolangModAnalyzer.class);
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "Golang";

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Golang Mod Analyzer";

    /**
     * Lock file name.
     * Please note that go.sum is NOT considered a lock file and may contain
     * dependencies that are no longer used and dependencies of dependencies.
     * According to here, go.mod should be used for reproducible builds:
     * https://github.com/golang/go/wiki/Modules#is-gosum-a-lock-file-why-does-gosum-include-information-for-module-versions-i-am-no-longer-using
     */
    private static final String GO_MOD = "go.mod";

    /**
     * The file filter for Gopkg.lock
     */
    private static final FileFilter GO_MOD_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(GO_MOD)
            .build();

    /**
     * Returns the name of the Golang Mode Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the key name for the analyzers enabled setting.
     *
     * @return the key name for the analyzers enabled setting
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_GOLANG_DEP_ENABLED;
    }

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return GO_MOD_FILTER;
    }

    private String getGo() {
        final String goPath = getSettings().getString(Settings.KEYS.ANALYZER_GOLANG_PATH);

        if (goPath == null) {
            LOGGER.warn(
                    "Path to `go` executable not set. Trying default location. If you do want to set it, please set the `{}` property",
                    Settings.KEYS.ANALYZER_GOLANG_PATH
            );
            return "go";
        } else {
            File goFile = new File(goPath);
            if (goFile.isFile()) {
                return goFile.getAbsolutePath();
            }
        }

        LOGGER.warn("Path to `go` exec executable does not exist: {}. Trying default location", goPath);
        return "go";
    }

    private Process launchGoMod(File folder) throws AnalysisException {
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }

        final List<String> args = new ArrayList<>();
        args.add(getGo());
        args.add("mod");
        args.add("edit");
        args.add("-json");

        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(folder);
        try {
            LOGGER.info("Launching: {} from {}", args, folder);
            return builder.start();
        } catch (IOException ioe) {
            throw new AnalysisException("go initialization failure; this error can be ignored if you are not analyzing Go. "
                    + "Otherwise ensure that go is installed and the path to go is correctly specified", ioe);
        }
    }

    /**
     * No-op initializer implementation.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        setEnabled(false);
        final Process process;
        try {
            process = launchGoMod(getSettings().getTempDirectory());
        } catch (AnalysisException ae) {
            final String msg = String.format("Exception from go process: %s. Disabling %s", ae.getCause(), ANALYZER_NAME);
            throw new InitializationException(msg, ae);
        } catch (IOException ex) {
            throw new InitializationException("Unable to create temporary file, the Go Mod Analyzer will be disabled", ex);
        }

        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ex) {
            final String msg = String.format("Go mod process was interrupted. Disabling %s", ANALYZER_NAME);
            Thread.currentThread().interrupt();
            throw new InitializationException(msg);
        }

        final int expectedNoModuleFoundExitValue = 1;
        final int possiblyGoTooOldExitValue = 2;
        final int goExecutableNotFoundExitValue = 127;

        System.out.println("Exitval: " + exitValue);
        switch (exitValue) {
            case expectedNoModuleFoundExitValue:
                setEnabled(true);
                LOGGER.info("{} is enabled.", ANALYZER_NAME);
                return;
            case goExecutableNotFoundExitValue:
                throw new InitializationException(String.format("Go executable not found. Disabling %s: %s", ANALYZER_NAME, exitValue));
            case possiblyGoTooOldExitValue:
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                    if (!reader.ready()) {
                        LOGGER.warn("Go mod error stream unexpectedly not ready. Disabling {}", ANALYZER_NAME);
                        throw new InitializationException("Go mod error stream unexpectedly not ready.");
                    } else {
                        final String line = reader.readLine();
                        if (line.contains("unknown subcommand \"mod\"")) {
                            LOGGER.warn("Your version of `go` does not support modules. Disabling {}. Error: `{}`", ANALYZER_NAME, line);
                            throw new InitializationException("Go version does not support modules.");
                        }
                    }
                } catch (UnsupportedEncodingException ex) {
                    throw new InitializationException("Unexpected go encoding.", ex);
                } catch (IOException ex) {
                    throw new InitializationException("Unable to read go output.", ex);
                }
            default:
                final String msg = String.format("Unexpected exit code from go process. Disabling %s: %s", ANALYZER_NAME, exitValue);
                throw new InitializationException(msg);
        }
    }

    /**
     * Analyzes go packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine     the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error
     *                           analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        //do not report on the build file itself
//        engine.removeDependency(dependency);

        final File parentFile = dependency.getActualFile().getParentFile();
        final Process process = launchGoMod(parentFile);

        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("go process interrupted", ie);
        }
        if (exitValue < 0 || exitValue > 1) {
            final String msg = String.format("Unexpected exit code from go process; exit code: %s", exitValue);
            throw new AnalysisException(msg);
        }
        try {
            try (BufferedReader errReader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                while (errReader.ready()) {
                    final String error = errReader.readLine();
                    LOGGER.warn(error);
                }
            }
            final GoModJsonParser parser = new GoModJsonParser(process.getInputStream());
            parser.process();
            parser.getDependencies().forEach(System.out::println);
        } catch (IOException ioe) {
            LOGGER.warn("go mod failure", ioe);
        }

    }
}
