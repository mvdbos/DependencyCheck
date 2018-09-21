package org.owasp.dependencycheck.analyzer;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.io.File;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

public class GolangDepAnalyzerTest extends BaseTest {

  private GolangDepAnalyzer analyzer;
  private Engine engine;

  @Override
  @Before
  public void setUp() throws Exception {
    super.setUp();
    analyzer = new GolangDepAnalyzer();
    engine = new Engine(this.getSettings());
  }

  @Test
  public void testName() {
    assertEquals("Analyzer name wrong.", "Golang Dep Analyzer",
        analyzer.getName());
  }

  @Test
  public void testSupportsFiles() {
    assertThat(analyzer.accept(new File("Gopkg.lock")), is(true));
  }

  @Test
  public void testGopkgLock() throws AnalysisException {
    final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "golang/Gopkg.lock"));
    analyzer.analyze(result, engine);
  }
}
