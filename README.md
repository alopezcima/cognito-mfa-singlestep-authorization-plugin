# Cognito MFA single-step GoCD Authorization Plugin

[![Build Status](https://travis-ci.org/BBVA/cognito-mfa-singlestep-authorization-plugin.svg?branch=master)](https://travis-ci.org/BBVA/cognito-mfa-singlestep-authorization-plugin)

GoCD plugin for Cognito User Pools. Allowing TOTP MFA authentication in a single step rather than two.

## Deployment

Start GoCD with the following environment variable set:

```plain
GOCD_PLUGIN_INSTALL_cognito-mfa-singlestep-authorization=https://github.com/BBVA/cognito-mfa-singlestep-authorization-plugin/releases/download/v0.2.2/cognito-mfa-singlestep-authorization-plugin-0.2.2.jar
```

## Plugin Configuration

Afterwards you can use the user interface configuration wizard to configure the plugin.

Alternatively you can set the configuration in `cruise-config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<cruise xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="cruise-config.xsd"
        schemaVersion="124">
    <server>
        <security>
            <authConfigs>
                <authConfig id="cognito" pluginId="cd.go.authorization.cognito-mfa-singlestep">
                    <property>
                        <key>ClientId</key>
                        <value>...</value>
                    </property>
                    <property>
                        <key>RegionName</key>
                        <value>...</value>
                    </property>
                    <property>
                        <key>AppSecret</key>
                        <value>...</value>
                    </property>
                    <property>
                        <key>UserPoolId</key>
                        <value>...</value>
                    </property>
                    <property>
                        <key>ExecutionRoleARN</key>
                        <value>...</value>
                    </property>
                </authConfig>
            </authConfigs>
        </security>
        <backup emailOnSuccess="true" emailOnFailure="true"/>
    </server>
</cruise>
```

With the proper values for:

- *ClientId*: Should match the *App client id* of your Cognito User Pool App.
- *RegionName*: The name of the AWS region where your User Pool lives. i.e. *eu-west-1*
- *AppSecret*: The Cognito User Poll App Secret. This parameter is optional, and it must be set if the Cognito Application Client has a secret.
- *UserPoolId*: The Cognito User Pool ID. The parameter is optional, and it is used only if the GoCD Plugin validate GoCD authentication tokens.
- *ExecutionRoleARN*: The AWS role to be assumed when execution AWS commands. This parameter is optional, and it used only to validate GoCD authentication tokens and the default AWS user role does not have permission to execute read Cognito commands.

## Cognito Configuration

In the configuration settings of your Cognito User Pool make sure that:

- *Do you want to enable Multi-Factor Authentication (MFA)?* is set as **Required**.
- *Which second factors do you want to enable?* have only the option **Time-based One-time Password** checked.

Also the Cognito User Pool App must:

- Have *Enabled Identity Providers* **checked**.
- Have *Enable username-password (non-SRP) flow for app-based authentication (USER_PASSWORD_AUTH)* **checked**.

## Usage

With the plugin set and running you can use your Cognito User Pool **username** in GoCD for authentication.
As the GoCD login page is not customizable you must use the password field to enter both your password and TOTP code.

### Example

- *Username:* myuser
- *Password:* mypassword
- *TOTP*: 123456

To authenticate in GoCD with the given credentials you should type:

![login](./login.png)
