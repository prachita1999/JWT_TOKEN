package com.example.librerymanegement.JWT;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.librerymanegement.Repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAutheticationFilter extends OncePerRequestFilter {

	@Autowired
	private final JwtService jwtService;

	@Autowired
	private final UserRepository userRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		final String authHeader = request.getHeader("Authorization");
		final String jwtToken;
		final String username;

		// Check if Authorization header is present and starts with "Bearer"
		if (authHeader == null || !authHeader.startsWith("Bearer")) {
			filterChain.doFilter(request, response);
			return;
		}

		// Extract JWTtoken from header
		jwtToken = authHeader.substring(7);
		username = jwtService.extractUsername(jwtToken);

		// check if we have a username and no authentication exist yet
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null)
			;

		// Get the details from databases;
		var userDetails = userRepository.findByUsername(username)
				.orElseThrow(() -> new RuntimeException("User not found"));

		// validate the token
		if (jwtService.isTokenValid(jwtToken, userDetails)) {

			
			//Create  the authetication with user roles
			List<SimpleGrantedAuthority> authorities = userDetails.getRoles().stream()
					                                   .map(SimpleGrantedAuthority::new)
					                                   .collect(Collectors.toList());

			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
					                                            userDetails, 
					                                            null,
					                                            authorities
                   );
			
			       //set authentication details
			     authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			
                // Update Security context with authentication
			     SecurityContextHolder.getContext().setAuthentication(authToken);
			     
		         }
	         }
                 filterChain.doFilter(request, response);    
	}
}

