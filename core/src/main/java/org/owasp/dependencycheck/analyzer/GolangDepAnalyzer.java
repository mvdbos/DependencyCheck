package org.owasp.dependencycheck.analyzer;

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

@ThreadSafe
public class GolangDepAnalyzer extends AbstractFileTypeAnalyzer {
  /**
   * A descriptor for the type of dependencies processed or added by this
   * analyzer.
   */
  public static final String DEPENDENCY_ECOSYSTEM = "Golang.dep";

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
   * @param engine     the engine being used to perform the scan
   *
   * @throws AnalysisException thrown if there is an unrecoverable error
   *                           analyzing the dependency
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
    for (Toml lock : projectsLocks) {
      final String name = lock.getString("name");
      final Dependency dep = new Dependency(new File(name), true);
      dep.setName(name);

      System.out.println(name);
      if (name != null && !name.isEmpty()) {
        dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "name", name, Confidence.HIGHEST);
      }

      final String version = lock.getString("version");
      System.out.println(version);
      if (version != null && version.isEmpty()) {
        dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "version", version, Confidence.HIGHEST);
      }

      final String revision = lock.getString("revision");
      System.out.println(revision);
      if (revision != null && revision.isEmpty()) {
        dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "revision", revision, Confidence.HIGHEST);
      }

      final List<String> packages = lock.getList("packages");
      for (String pkg : packages) {
        System.out.println(pkg);
        if (pkg != null && !pkg.isEmpty() && !pkg.equals(".")) {
          dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "package", revision, Confidence.HIGHEST);
        }
      }

      engine.addDependency(dep);
    }
  }
}
