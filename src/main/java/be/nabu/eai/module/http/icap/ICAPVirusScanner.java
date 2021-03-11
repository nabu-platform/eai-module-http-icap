package be.nabu.eai.module.http.icap;

import java.io.InputStream;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.api.VirusInfection;
import be.nabu.eai.repository.api.VirusScanner;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPEntity;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.icap.ICAPUtils;
import be.nabu.libs.resources.api.ResourceContainer;
import be.nabu.libs.services.api.ServiceException;
import be.nabu.utils.security.SSLContextType;

public class ICAPVirusScanner extends JAXBArtifact<ICAPVirusScannerConfiguration> implements VirusScanner {

	public ICAPVirusScanner(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "virus-scanner.xml", ICAPVirusScannerConfiguration.class);
	}

	@Override
	public VirusInfection scan(HTTPEntity entity) throws ServiceException {
		if (entity instanceof HTTPRequest) {
			try {
				final be.nabu.libs.http.icap.VirusInfection infection = ICAPUtils.scan(
					(HTTPRequest) entity, 
					getConfig().getHost(), 
					getConfig().getPath(), 
					getConfig().isSecure(), 
					getConfig().isSecure() && getConfig().getKeystore() != null ? getConfig().getKeystore().getKeyStore().newContext(SSLContextType.TLS) : null, 
					// connection timeout
					10000,
					// socket timeout
					30000
				);
				return infection == null 
					? null
					: ICAPVirusInfection.from(infection);
			}
			catch (HTTPException e) {
				throw new ServiceException("ICAP-" + e.getCode(), e.getMessage(), e);
			}
			catch (Exception e) {
				throw new ServiceException("ICAP-1", "Could not scan request", e);
			}
		}
		return null;
	}

	@Override
	public VirusInfection scan(InputStream input) throws ServiceException {
		try {
			final be.nabu.libs.http.icap.VirusInfection infection = ICAPUtils.scan(
				input, 
				getConfig().getHost(), 
				getConfig().getPath(), 
				getConfig().isSecure(), 
				getConfig().isSecure() && getConfig().getKeystore() != null ? getConfig().getKeystore().getKeyStore().newContext(SSLContextType.TLS) : null, 
				// connection timeout
				10000,
				// socket timeout
				30000
			);
			return infection == null 
				? null
				: ICAPVirusInfection.from(infection);
		}
		catch (HTTPException e) {
			throw new ServiceException("ICAP-" + e.getCode(), e.getMessage(), e);
		}
		catch (Exception e) {
			throw new ServiceException("ICAP-2", "Could not scan stream", e);
		}
	}

}
