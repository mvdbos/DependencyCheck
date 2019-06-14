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
 * Copyright (c) 2019 Matthijs van den Bos. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.InitializationException;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

/**
 * Unit tests for GolangModAnalyzer.
 *
 * @author Matthijs van den Bos
 */
public class GolangModAnalyzerTest extends BaseTest {

    private GolangModAnalyzer analyzer;
    private Engine engine;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new GolangModAnalyzer();
        engine = new Engine(this.getSettings());
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        if (analyzer != null) {
            analyzer.close();
            analyzer = null;
        }
        super.tearDown();
    }


    @Test
    public void testName() {
        assertEquals("Analyzer name wrong.", "Golang Mod Analyzer",
                analyzer.getName());
    }

    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("go.mod")), is(true));
    }

    @Test
    public void testGoMod() throws AnalysisException, InitializationException, ExceptionCollection {
        analyzer.prepare(engine);
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "golang/go.mod"));
        analyzer.analyze(result, engine);

        assertEquals(3, engine.getDependencies().length);

        boolean found = false;
        for (Dependency d : engine.getDependencies()) {
            if ("gitea".equals(d.getName())) {
                found = true;
                assertEquals("1.5.0", d.getVersion());
                assertEquals(d.getDisplayFileName(), "github.com/go-gitea/gitea:1.5.0");
                assertEquals(GolangModAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                assertTrue(d.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("go-gitea"));
                assertTrue(d.getEvidence(EvidenceType.PRODUCT).toString().toLowerCase().contains("gitea"));
                assertTrue(d.getEvidence(EvidenceType.VERSION).toString().toLowerCase().contains("1.5.0"));
            }
        }
        assertTrue("Expected to find gitea/gitea", found);
    }
}
