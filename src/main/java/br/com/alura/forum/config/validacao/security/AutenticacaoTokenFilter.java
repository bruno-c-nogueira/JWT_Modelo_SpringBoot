package br.com.alura.forum.config.validacao.security;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class AutenticacaoTokenFilter extends OncePerRequestFilter {

    private TokenService tokenService;
    private UsuarioRepository repository;
    public AutenticacaoTokenFilter(TokenService tokenService,UsuarioRepository repository) {
        this.tokenService = tokenService;
        this.repository = repository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String token = recuperarToken(httpServletRequest);
        System.out.println(token);
        boolean validado = tokenService.isTokenValido(token);
        if (validado){
            autenticarCliente(token);
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    private void autenticarCliente(String token) {
        Long idUsuario = tokenService.getIdUsuario(token);
        Usuario usuario = repository.findById(idUsuario).orElse(null);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario,null,usuario.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private String recuperarToken(HttpServletRequest httpServletRequest) {
        String token = httpServletRequest.getHeader("Authorization");
        if (token == null || token.isEmpty() || !token.startsWith("Bearer ")){
            return  null;
        }
        return  token.substring(7,token.length());
    }
}
