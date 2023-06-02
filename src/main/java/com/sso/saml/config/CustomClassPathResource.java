package com.sso.saml.config;

import org.joda.time.DateTime;
import org.opensaml.util.resource.AbstractFilteredResource;
import org.opensaml.util.resource.ResourceException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

/**
 * @author jian.xiong
 * @title: CustomClassPathResource
 * @projectName sfbackend
 * @description: TODO
 * @date 2022-07-18
 */
public class CustomClassPathResource extends AbstractFilteredResource {
    private URL resource;
    private DateTime lastModTime;

    public CustomClassPathResource(URL resource) throws ResourceException {
        if (resource == null) {
            throw new ResourceException("Classpath resource does not exist");
        } else {
            this.resource = resource;
            this.lastModTime = new DateTime();
        }
    }


    public boolean exists() {
        return this.resource != null;
    }

    @Override
    public InputStream getInputStream() {
        if (this.resource != null) {
            try {
                return this.resource.openStream();
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        return null;
    }


    public DateTime getLastModifiedTime() throws ResourceException {
        return this.lastModTime;
    }

    public String getLocation() {
        return this.resource.toString();
    }

    public String toString() {
        return this.getLocation();
    }

    public int hashCode() {
        return this.getLocation().hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else {
            return o instanceof org.opensaml.util.resource.ClasspathResource ? this.getLocation().equals(((org.opensaml.util.resource.ClasspathResource) o).getLocation()) : false;
        }
    }
}

