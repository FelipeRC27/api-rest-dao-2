package com.idat.idatapirest.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.idat.idatapirest.dto.ProductRequestDTO;
import com.idat.idatapirest.dto.ProductResponseDTO;
import com.idat.idatapirest.model.Products;
import com.idat.idatapirest.service.ProductService;

@RestController
@RequestMapping("/producto/v1")
public class ProductController {

	@Autowired
	private ProductService service;
	
	@RequestMapping(method = RequestMethod.GET, path = "/listar")
	public ResponseEntity<List<ProductResponseDTO>>listar(){
		return new ResponseEntity<List<ProductResponseDTO>>	(service.listarProductos(),HttpStatus.OK);	
	}
	
	@RequestMapping(method = RequestMethod.POST, path = "/guardar")
	public ResponseEntity<Void> guardar(@RequestBody ProductRequestDTO producto){
		service.guardarProducto(producto);
		return new ResponseEntity<Void>(HttpStatus.CREATED);
	}
	
	
	@RequestMapping(method = RequestMethod.GET, path = "/listar/{id}")
	public @ResponseBody ResponseEntity<ProductResponseDTO> productById(@PathVariable Integer id){
		ProductResponseDTO product = service.productById(id);
		if(product != null) {
			return new ResponseEntity<ProductResponseDTO>(product, HttpStatus.OK);

		}
		return new ResponseEntity<ProductResponseDTO>(HttpStatus.NOT_FOUND);

	}
	
	@RequestMapping(method = RequestMethod.DELETE, path = "/eliminar/{id}")
	public ResponseEntity<Void> eliminar(@PathVariable Integer id){
		ProductResponseDTO product = service.productById(id);
		if(product != null) {
			service.eliminarProducto(id);
			return new ResponseEntity<Void>(HttpStatus.OK);
		}
		return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);

	}
	
	@RequestMapping(method = RequestMethod.PUT, path = "/editar")
	public ResponseEntity<Void> editar(@RequestBody ProductRequestDTO producto){
		ProductResponseDTO product = service.productById(producto.getIdRequest());
		if(product != null) {
			service.editarProducto(producto);
			return new ResponseEntity<Void>(HttpStatus.OK);
		}
		return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
	}

	
}
