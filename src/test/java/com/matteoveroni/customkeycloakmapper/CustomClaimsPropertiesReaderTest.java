package com.matteoveroni.customkeycloakmapper;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class CustomClaimsPropertiesReaderTest {

    @Test
    public void test_read_custom_claims_from_resources() {
        List<String> customClaims = CustomClaimsPropertiesReader.loadCustomClaimsFromConfig(CustomProtocolMapper.DEFAULT_CONFIG_PROPERTIES);

        assertTrue(customClaims.contains("test1"), "Error, expected value not read from resources!");
        assertTrue(customClaims.contains("test2"), "Error, expected value not read from resources!");
    }

    @ParameterizedTest
    @ValueSource(strings = {"keycloak-empty-mapper.properties", "keycloak-null-mapper.properties"})
    public void test_read_empty_custom_claims_from_resources(String invalidConfigFile) {
        List<String> customClaims = CustomClaimsPropertiesReader.loadCustomClaimsFromConfig(invalidConfigFile);

        assertTrue(customClaims.isEmpty(), String.format("Error, some custom claims found (%s)!", invalidConfigFile));
    }
}