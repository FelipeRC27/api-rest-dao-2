package com.idat.idatapirest.service;

import java.util.List;

import com.idat.idatapirest.dto.ProductRequestDTO;
import com.idat.idatapirest.dto.ProductResponseDTO;
import com.idat.idatapirest.model.Products;

public interface ProductService {

	public void guardarProducto(ProductRequestDTO p);
	public void eliminarProducto(Integer id);
	public void editarProducto(ProductRequestDTO p);
	public List<ProductResponseDTO> listarProductos();
	public ProductResponseDTO productById(Integer id);
	
}
