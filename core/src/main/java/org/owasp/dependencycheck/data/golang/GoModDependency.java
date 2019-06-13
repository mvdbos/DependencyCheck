package org.owasp.dependencycheck.data.golang;

import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.dependency.Dependency;

public class GoModDependency {
    private String modulePath;
    private String version;

    private PackageURLBuilder packageURLBuilder;

    public GoModDependency(String modulePath, String version) {
        this.modulePath = modulePath;
        this.version = version;

        packageURLBuilder = PackageURLBuilder.aPackageURL().withType("golang");
    }
    public String getModulePath() {
        return modulePath;
    }

    public String getVersion() {
        return version;
    }

    public Dependency toDependency(Dependency parentDependency) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);

        return dep;
    }



    @Override
    public String toString() {
        return modulePath + ": " + version;
    }
}

