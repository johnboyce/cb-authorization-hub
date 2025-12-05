package com.connellboyce.authhub.model.dao;

import io.quarkus.mongodb.panache.common.MongoEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.codecs.pojo.annotations.BsonId;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@MongoEntity(collection = "users")
public class CBUser {
	@BsonId
	private String id;
	private String username;
	private String password;
	private Set<String> roles;
	private String email;
	private String firstName;
	private String lastName;

}
