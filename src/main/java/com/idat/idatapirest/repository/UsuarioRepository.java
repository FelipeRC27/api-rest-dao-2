package com.idat.idatapirest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.idat.idatapirest.model.Usuario;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Integer>{
	
	//El similar a selecr*from Usuario where usuario= ?
	Usuario findByUsuario(String usuario);
		
	
	

}
