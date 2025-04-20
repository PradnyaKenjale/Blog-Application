package com.blog.payloads;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class JwtAuthResponse {

	private String token;
}
