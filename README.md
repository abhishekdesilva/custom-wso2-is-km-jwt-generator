# custom-wso2-is-km-jwt-generator

This is a custom JWT genreator which is similar to [1]. The only addition here is in the JWT body, it adds the OAuth access token with the key "jti".

To plug this to the WSO2 server (Key Manager), modify the api-manager.xml file and add following.

    <JWTConfiguration>
        <JWTGeneratorImpl>com.wso2.custom.jwt.generator.JWTGenerator</JWTGeneratorImpl>

[1] https://github.com/wso2/carbon-apimgt/blob/v6.1.66/components/apimgt/org.wso2.carbon.apimgt.keymgt/src/main/java/org/wso2/carbon/apimgt/keymgt/token/JWTGenerator.java
