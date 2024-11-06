/*
* Copyright (C) 2020 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.eai.module.http.icap;

import be.nabu.eai.repository.api.VirusInfection;

public class ICAPVirusInfection implements VirusInfection {
	
	public static ICAPVirusInfection from(be.nabu.libs.http.icap.VirusInfection infection) {
		ICAPVirusInfection result = new ICAPVirusInfection();
		result.setThreat(infection.getThreat());
		result.setResolution(infection.getResolution());
		result.setType(infection.getType());
		return result;
	}

	private String threat, resolution, type;

	@Override
	public String getThreat() {
		return threat;
	}
	public void setThreat(String threat) {
		this.threat = threat;
	}

	public String getResolution() {
		return resolution;
	}
	public void setResolution(String resolution) {
		this.resolution = resolution;
	}

	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	
}
