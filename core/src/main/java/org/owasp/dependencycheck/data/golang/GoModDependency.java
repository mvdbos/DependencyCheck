package org.owasp.dependencycheck.data.golang;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.owasp.dependencycheck.analyzer.GolangModAnalyzer.DEPENDENCY_ECOSYSTEM;
import static org.owasp.dependencycheck.analyzer.GolangModAnalyzer.GO_MOD;

public class GoModDependency {
    /**
     * The logger.
     */
    private static final Logger LOGGER =LoggerFactory.getLogger(GoModDependency .class);

    private String modulePath;
    private String version;
    private String revision = null;

    private PackageURLBuilder packageURLBuilder;

    public GoModDependency(String modulePath, String version) {
        this.modulePath = modulePath;
        this.version = version;

        if (this.version.contains("-")) {
            String[] versionElements = this.version.split("-");
            revision = versionElements[versionElements.length - 1];
        }
        packageURLBuilder = PackageURLBuilder.aPackageURL().withType("golang");
    }

    public String getModulePath() {
        return modulePath;
    }

    public String getVersion() {
        return version;
    }

    public Dependency toDependency(Dependency parentDependency) {
        return createDependency(parentDependency, modulePath, version, revision, null);
    }

    /**
     * Builds a dependency object based on the given data.
     *
     * @param parentDependency a reference to the parent dependency
     * @param name             the name of the dependency
     * @param version          the version of the dependency
     * @param revision         the revision of the dependency
     * @param subPath          the sub-path of the dependency
     * @return a new dependency object
     */
    private Dependency createDependency(Dependency parentDependency, String name, String version, String revision, String subPath) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);
        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);

        if (StringUtils.isNotBlank(subPath)) {
            dep.setDisplayFileName(name + "/" + subPath);
            dep.setName(name + "/" + subPath);
        } else {
            dep.setDisplayFileName(name);
            dep.setName(name);
        }

        String baseNamespace = null;
        String depNamespace = null;
        String depName = null;
        if (StringUtils.isNotBlank(name)) {
            final int slashPos = name.indexOf("/");
            if (slashPos > 0) {
                baseNamespace = name.substring(0, slashPos);
                final int lastSlash = name.lastIndexOf("/");
                depName = name.substring(lastSlash + 1);
                if (lastSlash != slashPos) {
                    depNamespace = name.substring(slashPos + 1, lastSlash);
                    dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "namespace", depNamespace, Confidence.HIGH);
                    dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "namespace", depNamespace, Confidence.HIGH);
                    packageURLBuilder.withNamespace(baseNamespace + "/" + depNamespace);
                } else {
                    packageURLBuilder.withNamespace(baseNamespace);
                }
                packageURLBuilder.withName(depName);
                dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "namespace", baseNamespace, Confidence.LOW);
                dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "namespace", baseNamespace, Confidence.LOW);

                dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "name", depName, Confidence.HIGHEST);
                dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "name", depName, Confidence.HIGHEST);
            } else {
                packageURLBuilder.withName(name);
                dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "namespace", name, Confidence.HIGHEST);
                dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "namespace", name, Confidence.HIGHEST);
            }
        }
        if (StringUtils.isNotBlank(version)) {
            packageURLBuilder.withVersion(version);
            dep.setVersion(version);
            dep.addEvidence(EvidenceType.VERSION, GO_MOD, "version", version, Confidence.HIGHEST);
        }
        if (StringUtils.isNotBlank(revision)) {
            if (version == null) {
                //this is used to help determine the actual version in the NVD - a commit hash doesn't work
                // instead we need to make it an asterik for the CPE...
                //dep.setVersion(revision);
                packageURLBuilder.withVersion(version);
            }
            //Revision (which appears to be a commit hash) won't be of any value in the analysis.
            //dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "revision", revision, Confidence.HIGHEST);
        }
        if (StringUtils.isNotBlank(subPath)) {
            packageURLBuilder.withSubpath(subPath);
            dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "package", subPath, Confidence.HIGH);
            dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "package", subPath, Confidence.MEDIUM);
        }

        Identifier id;
        PackageURL purl = null;
        try {
            purl = packageURLBuilder.build();
            id = new PurlIdentifier(packageURLBuilder.build(), Confidence.HIGHEST);
        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Unable to create package-url identifier for `{}` in `{}` - reason: {}", name, parentDependency.getFilePath(), ex.getMessage());
            StringBuilder value = new StringBuilder(name);
            if (StringUtils.isNotBlank(subPath)) {
                value.append("/").append(subPath);
            }
            if (StringUtils.isNotBlank(version)) {
                value.append("@").append(version);
            }
            id = new GenericIdentifier(value.toString(), Confidence.HIGH);
        }
        dep.addSoftwareIdentifier(id);
        return dep;
    }


    @Override
    public String toString() {
        return modulePath + ": " + version;
    }
}

