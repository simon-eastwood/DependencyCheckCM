/*
Version of the Nexus Analyer which reads the CPE identifier from Nexus custom metadata.
This allows a Nexus administrator to ensure that a given jar file is correctly identified by DependencyCheck (in case it cant figure it out for itself), and then find any security violations for that jar.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nexus.NexusSearch;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory; 
import javax.xml.xpath.XPath; 
import javax.xml.xpath.XPathFactory; 
import org.owasp.dependencycheck.utils.InvalidSettingException; 
import org.owasp.dependencycheck.utils.Settings; 
import org.owasp.dependencycheck.utils.URLConnectionFactory; 
import org.w3c.dom.Document; 
import org.owasp.dependencycheck.dependency.Identifier;

/**
 * Analyzer which will attempt to locate a dependency on a Nexus service by SHA-1 digest of the dependency,
 * and then see if there is any custom metadata set for that artefact. If there is, it will use the metadata to set the cpe identifier
 *
 * There are two settings which govern this behavior:
 *
 * <ul>
 * <li>{@link org.owasp.dependencycheck.utils.Settings.KEYS#ANALYZER_NEXUS_ENABLED} determines whether this analyzer is
 * even enabled. This can be overridden by setting the system property.</li>
 *This analyzer is derived from the Nexus Analyzer and uses the same settings in order to connect to Nexus 
 * 
 * <li>{@link org.owasp.dependencycheck.utils.Settings.KEYS#ANALYZER_NEXUS_URL} the URL to a Nexus service to search by
 * SHA-1. There is an expected <code>%s</code> in this where the SHA-1 will get entered.</li>
 * </ul>
 *
 * @author seastwood
 */
public class NexusCMAnalyzer extends NexusAnalyzer {


    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(NexusCMAnalyzer.class.getName());

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Nexus CM Analyzer";

    /**
     * The phase in which the analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.IDENTIFIER_ANALYSIS;

    /**
     * The types of files on which this will work.
     */
    private static final Set<String> SUPPORTED_EXTENSIONS = newHashSet("jar");

    /**
     * The Nexus Search to be set up for this analyzer.
     */
    private NexusSearch searcher;

    /**
     * Field indicating if the analyzer is enabled.
     */
    private final boolean enabled = checkEnabled();

    /**
     * Determines if this analyzer is enabled
     *
     * @return <code>true</code> if the analyzer is enabled; otherwise <code>false</code>
     */
    protected boolean checkEnabled() {
        /* Enable this analyzer ONLY if the Nexus URL has been set to something
         other than the default one and it's enabled by the user.
         */
        boolean retval = false;
        try {
            if ((!DEFAULT_URL.equals(Settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL)))
                    && Settings.getBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED)) {
                LOGGER.info("Enabling Nexus CM analyzer");
                retval = true;
            } else {
                LOGGER.fine("Nexus CM analyzer disabled");
            }
        } catch (InvalidSettingException ise) {
            LOGGER.warning("Invalid setting. Disabling Nexus CM analyzer");
        }

        return retval;
    }

    /**
     * Determine whether to enable this analyzer or not.
     *
     * @return whether the analyzer should be enabled
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @throws Exception if there's an error during initialization
     */
    @Override
    public void initializeFileTypeAnalyzer() throws Exception {
        LOGGER.fine("Initializing Nexus CM Analyzer");
        LOGGER.fine(String.format("Nexus CM Analyzer enabled: %s", isEnabled()));
        if (isEnabled()) {
            final String searchUrl = Settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
            LOGGER.fine(String.format("Nexus CM Analyzer URL: %s", searchUrl));
            try {
                searcher = new NexusSearch(new URL(searchUrl));
                if (!searcher.preflightRequest()) {
                    LOGGER.warning("There was an issue getting Nexus CM status. Disabling Nexus CM analyzer.");
                    setEnabled(false);
                }
            } catch (MalformedURLException mue) {
                // I know that initialize can throw an exception, but we'll
                // just disable the analyzer if the URL isn't valid
                LOGGER.warning(String.format("Property %s not a valid URL. Nexus CM Analyzer disabled", searchUrl));
                setEnabled(false);
            }
        }
    }

    /**
     * Returns the analyzer's name.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NEXUS_ENABLED;
    }

    /**
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which this analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Returns the extensions for which this Analyzer runs.
     *
     * @return the extensions for which this Analyzer runs
     */
    @Override
    public Set<String> getSupportedExtensions() {
        return SUPPORTED_EXTENSIONS;
    }

    /**
     * Performs the analysis.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine
     * @throws AnalysisException when there's an exception during analysis
     */
    @Override
    public void analyzeFileType(Dependency dependency, Engine engine) throws AnalysisException {
        if (!isEnabled()) {
            return;
        }
        try {
            final MavenArtifact ma = searcher.searchSha1(dependency.getSha1sum());
            
            getCMFromNexus(repo, ma.getGroupId(), ma.getArtifactId(), ma.getVersion(), dependency);
            
            
            
        } catch (IllegalArgumentException iae) {
            
            LOGGER.info(String.format("invalid sha-1 hash on %s", dependency.getFileName()));
        } catch (FileNotFoundException fnfe) {
            
            LOGGER.fine(String.format("Artifact not found in repository '%s'", dependency.getFileName()));
            LOGGER.log(Level.FINE, fnfe.getMessage(), fnfe);
        } catch (IOException ioe) {
            
            LOGGER.log(Level.FINE, "Could not connect to nexus repository", ioe);
        }
    }


    /**
     * Calls Nexus to get metadata
     *
     * @param repo the name of the repository in which the artifact can be found
     * @param grpId the group id
     * @param artId  the art id
     * @param version  the version number
     * @dependency  the dependency which will be enriched with information from Nexus Custom Metadata if any
     * @throws AnalysisException when there's an exception during analysis
     */
    
protected void getCMFromNexus (String repo, String grpId, String artId, String version, Dependency dependency) throws IOException, FileNotFoundException {
    
    // construct id needed to query custom metadata
    // example id needed : urn:maven/artifact#abbot:abbot:1.0.1::jar
    String artifactIdentifier =  "urn:maven/artifact#" +
                                        grpId + ":" +
                                        artId + ":" +
                                        version + "::jar";
    byte[]   bytesEncoded = Base64.encodeBase64(artifactIdentifier.getBytes());
    
   final URL url = new URL(rootURL, String.format("index/custom_metadata/%s/%s", 
                 repo, newString (bytesEncoded) ); 
 
    LOGGER.fine(String.format("Retrieving custom metadata from Nexus url %s", url.toString()));
    
    
    final HttpURLConnection conn = URLConnectionFactory.createHttpURLConnection(url, false /*dont use proxy*/ ); 

 
     conn.setDoOutput(true); 
 
 
     conn.addRequestProperty("Accept", "application/xml"); 
     conn.connect(); 
 
 
     if (conn.getResponseCode() == 200) { 
     try { 
         final DocumentBuilder builder = DocumentBuilderFactory 
                         .newInstance().newDocumentBuilder(); 
                 final Document doc = builder.parse(conn.getInputStream()); 
                 final XPath xpath = XPathFactory.newInstance().newXPath(); 
                 
                final String cpe = xpath 
                         .evaluate( 
                                 "/customMetadataResponse/data/customMetadata/key[text()='cpe']/../value", 
                                 doc); 
                                 
                Identifier id = new Identifier(cpe);
                id.setConfidence (Confidence.HIGHEST);
                dependency.addIdentifier(id);
                return;
             } catch (Throwable e) { 
                 // Anything else is jacked-up XML stuff that we really can't recover 
                 // from well 
                 throw new IOException(e.getMessage(), e); 
             } 
         } else if (conn.getResponseCode() == 404) { 
             throw new FileNotFoundException("Artifact not found in Nexus"); 
         } else { 
             final String msg = String.format("Could not connect to Nexus received response code: %d %s", 
                     conn.getResponseCode(), conn.getResponseMessage()); 
             LOGGER.fine(msg); 
             throw new IOException(msg); 
         } 
    
}


}

