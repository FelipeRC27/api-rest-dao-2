package com.idat.idatapirest.dto;

public class UsuarioRequestDTO {
	
	private String usuario;
	private String contrasenia;
	public String getUsuario() {
		return usuario;
	}
	public void setUsuario(String usuario) {
		this.usuario = usuario;
	}
	public String getContrasenia() {
		return contrasenia;
	}
	public void setContrasenia(String contrasenia) {
		this.contrasenia = contrasenia;
	}
	public UsuarioRequestDTO(String usuario, String contrasenia) {
		super();
		this.usuario = usuario;
		this.contrasenia = contrasenia;
	}
	public UsuarioRequestDTO() {
		super();
		// TODO Auto-generated constructor stub
	}
	
	
}
