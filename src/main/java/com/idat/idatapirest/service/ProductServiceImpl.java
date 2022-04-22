package com.idat.idatapirest.service;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.idat.idatapirest.dto.ProductRequestDTO;
import com.idat.idatapirest.dto.ProductResponseDTO;
import com.idat.idatapirest.model.Products;
import com.idat.idatapirest.repository.ProductRepository;

@Service
public class ProductServiceImpl implements ProductService {

	@Autowired
	private ProductRepository repository;
	
	@Override
	public void guardarProducto(ProductRequestDTO p) {
		Products producto = new Products();
		
		producto.setIdProducto(p.getIdRequest());
		producto.setDescripcion(p.getDescripcionProducto());
		producto.setNombreProducto(p.getNombreProducto());
		producto.setPrecio(p.getPrecioProducto());
		producto.setStock(p.getStockProducto());
		
		repository.save(producto);
	}

	@Override
	public void eliminarProducto(Integer id) {
		repository.deleteById(id);
	}

	@Override
	public void editarProducto(ProductRequestDTO p) {
		Products producto = new Products();
		
		producto.setIdProducto(p.getIdRequest());
		producto.setDescripcion(p.getDescripcionProducto());
		producto.setNombreProducto(p.getNombreProducto());
		producto.setPrecio(p.getPrecioProducto());
		producto.setStock(p.getStockProducto());		
		
		repository.saveAndFlush(producto);
	}

	@Override
	public List<ProductResponseDTO> listarProductos() {
		
		List<Products> producto = repository.findAll();
		
		List<ProductResponseDTO> dto = new ArrayList<ProductResponseDTO>();
		ProductResponseDTO productoDto = null;
		
		for (Products products : producto) {
			productoDto = new ProductResponseDTO();
			
			productoDto.setIdResponse(products.getIdProducto());
			productoDto.setNombreProducto(products.getNombreProducto());
			productoDto.setDescripcionProducto(products.getDescripcion());
			productoDto.setPrecioProducto(products.getPrecio());
			productoDto.setStockProducto(products.getStock());
			
			dto.add(productoDto);
		}
		return dto;
	}

	@Override
	public ProductResponseDTO productById(Integer id) {
		Products products = repository.findById(id).orElse(null);
		ProductResponseDTO productoDto = new ProductResponseDTO();
		
		productoDto = new ProductResponseDTO();		
		productoDto.setIdResponse(products.getIdProducto());
		productoDto.setNombreProducto(products.getNombreProducto());
		productoDto.setDescripcionProducto(products.getDescripcion());
		productoDto.setPrecioProducto(products.getPrecio());
		productoDto.setStockProducto(products.getStock());
		
		return productoDto;
		
	}

}
