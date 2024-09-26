package com.matteoveroni.customkeycloackmapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Properties;
import org.keycloak.theme.PropertiesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomClaimsPropertiesReader {

    private static final Logger log = LoggerFactory.getLogger(CustomClaimsPropertiesReader.class);

    private static final String KEYCLOACK_CUSTOM_CLAIMS = "keycloack.custom.claims";

    private CustomClaimsPropertiesReader() {
    }

    public static List<String> loadCustomClaimsFromConfig(String configPropFile) {
        Properties properties = loadPropertiesFromResources(configPropFile);
        String claims = properties.getProperty(KEYCLOACK_CUSTOM_CLAIMS, null);
        return claims == null || claims.isBlank()
                ? List.of()
                : List.of(claims.split(","));
    }

    private static Properties loadPropertiesFromResources(String resourceFilePath) {
        Properties properties = new Properties();
        try (InputStream input = PropertiesUtil.class.getResourceAsStream(resourceFilePath)) {
            if (input == null) {
                throw new IOException("File not found: " + resourceFilePath);
            }
            properties.load(input);
        } catch (IOException e) {
            log.warn("Error", e);
        }
        return properties;
    }
}