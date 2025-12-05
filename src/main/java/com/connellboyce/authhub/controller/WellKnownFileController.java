package com.connellboyce.authhub.controller;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@Path("")
public class WellKnownFileController {
	
	@GET
	@Path("/robots.txt")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getRobotsDotTxt() {
		try {
			return getTxtFileContents("robots.txt");
		} catch (IOException e) {
			return Response.serverError().build();
		}
	}

	@GET
	@Path("/.well-known/robots.txt")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getWellKnownRobotsDotTxt() {
		return getRobotsDotTxt();
	}

	@GET
	@Path("/humans.txt")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getHumansDotTxt() {
		try {
			return getTxtFileContents("humans.txt");
		} catch (IOException e) {
			return Response.serverError().build();
		}
	}

	@GET
	@Path("/.well-known/humans.txt")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getWellKnownHumansDotTxt() {
		return getHumansDotTxt();
	}

	private Response getTxtFileContents(String fileName) throws IOException {
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("META-INF/resources/static/" + fileName)) {
			if (is == null) {
				return Response.status(Response.Status.NOT_FOUND).build();
			}
			String contents = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			return Response.ok(contents).build();
		}
	}
}
