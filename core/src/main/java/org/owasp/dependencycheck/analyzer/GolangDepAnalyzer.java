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

import com.github.packageurl.PackageURLBuilder;
import java.io.File;
import java.io.FileFilter;
import java.util.List;

import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import com.moandjiezana.toml.Toml;

/**
 * Go lang dependency analyzer.
 *
 * @author Nima Yahyazadeh
 */
@ThreadSafe
@Experimental
public class GolangDepAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "Golang";

    /**
     * Lock file name.
     */
    private static final String GOPKG_LOCK = "Gopkg.lock";

    /**
     * The file filter for Gopkg.lock
     */
    private static final FileFilter GOPKG_LOCK_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(GOPKG_LOCK)
            .build();

    /**
     * Returns the name of the Python Package Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "Golang Dep Analyzer";
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
        return GOPKG_LOCK_FILTER;
    }

    /**
     * No-op initializer implementation.
     *
     * @param engine a reference to the dependency-check engine
     *
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // Nothing to do here.
    }

    /**
     * Analyzes go packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine being used to perform the scan
     *
     * @throws AnalysisException thrown if there is an unrecoverable error
     * analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);

        if (dependency.getFileName() == null || !GOPKG_LOCK_FILTER.accept(dependency.getActualFile())) {
            System.out.println("Didn't find any");
        }

        System.out.println(dependency);
        final Toml result = new Toml().read(dependency.getActualFile());
        final List<Toml> projectsLocks = result.getTables("projects");
        PackageURLBuilder packageBuilder = PackageURLBuilder.aPackageURL().withType("golang");
        for (Toml lock : projectsLocks) {
            final String name = lock.getString("name");
            final Dependency dep = new Dependency(dependency.getActualFile(), true);
            dep.setName(name);
            dep.setDisplayFileName(name);
            String pkgName = null;
            String depName = null;

            if (name != null && !name.isEmpty()) {
                final int slashPos = name.indexOf("/");
                if (slashPos>0) {
                    pkgName = name.substring(0, name.indexOf("/"));
                    depName = name.substring(pkgName.length() + 1);

                    packageBuilder.withNamespace(pkgName);
                    packageBuilder.withName(depName);
                    dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "namespace", pkgName, Confidence.LOW);
                    dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "namespace", pkgName, Confidence.LOW);

                    dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "name", depName, Confidence.HIGHEST);
                    dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "name", depName, Confidence.HIGHEST);
                } else {
                    packageBuilder.withName(name);
                    dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "namespace", name, Confidence.HIGHEST);
                    dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "namespace", name, Confidence.HIGHEST);
                }
            }

            final String version = lock.getString("version");
            if (version != null && version.isEmpty()) {
                packageBuilder.withVersion(version);
                dep.setVersion(version);
                dep.addEvidence(EvidenceType.VERSION, GOPKG_LOCK, "version", version, Confidence.HIGHEST);
            }

            final String revision = lock.getString("revision");
            if (revision != null && revision.isEmpty()) {
                if (version==null) {
                    dep.setVersion(revision);
                }
                //Revision (which appears to be a commit hash) won't be of any value in the analysis.
                //dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "revision", revision, Confidence.HIGHEST);
            }
            engine.addDependency(dep);
            
            final List<String> packages = lock.getList("packages");
            for (String pkg : packages) {
                System.out.println(pkg);
                if (pkg != null && !pkg.isEmpty() && !pkg.equals(".")) {
                    dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "package", revision, Confidence.HIGHEST);
                }
            }

            
        }
    }
}
