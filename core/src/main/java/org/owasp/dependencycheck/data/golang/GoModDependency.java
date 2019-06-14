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
import org.owasp.dependencycheck.utils.Checksum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.owasp.dependencycheck.analyzer.GolangModAnalyzer.DEPENDENCY_ECOSYSTEM;
import static org.owasp.dependencycheck.analyzer.GolangModAnalyzer.GO_MOD;

public class GoModDependency {
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GoModDependency.class);

    private String modulePath;
    private String version;
    private String revision = null;

    private PackageURLBuilder packageURLBuilder;

    public GoModDependency(String modulePath, String version) {
        this.modulePath = modulePath;
        this.version = version;

        int index = this.version.lastIndexOf("-");
        if (index > 0) {
            revision = this.version.substring(index + 1);
        }
        packageURLBuilder = PackageURLBuilder.aPackageURL().withType("golang");
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
    @SuppressWarnings("Duplicates")
    private Dependency createDependency(Dependency parentDependency, String name, String version, String revision, String subPath) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);

        String vendor = null;
        String moduleName = null;

        // find the bare name of the module, without vendor info
        final int lastSlash = name.lastIndexOf("/");
        if (lastSlash > 0) {
            vendor = name.substring(0, lastSlash);
            moduleName = name.substring(lastSlash + 1);
        } else {
            moduleName = name;
        }



        final String filePath = String.format("%s:%s/%s/%s", parentDependency.getFilePath(), vendor, moduleName, version);

        packageURLBuilder.withName(moduleName);
        packageURLBuilder.withNamespace(vendor);
        packageURLBuilder.withVersion(version);
        packageURLBuilder.withSubpath(subPath);

        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dep.setDisplayFileName(name + ":" + version);
        dep.setName(moduleName);
        dep.setVersion(version);
        dep.setPackagePath(String.format("%s:%s", name, version));
        dep.setFilePath(filePath);
        dep.setSha1sum(Checksum.getSHA1Checksum(filePath));
        dep.setSha256sum(Checksum.getSHA256Checksum(filePath));
        dep.setMd5sum(Checksum.getMD5Checksum(filePath));

        dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "namespace", vendor, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "name", moduleName, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VERSION, GO_MOD, "version", version, Confidence.HIGHEST);

        Identifier id;
        PackageURL purl = null;
        try {
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

