package com.idat.idatapirest.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Table(name = "products")
@Entity
public class Products implements Serializable{


	private static final long serialVersionUID = 6026109738059984351L;
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer idProducto;
	private String nombreProducto;
	private String descripcion;
	private Double precio;
	private Integer stock;
	
	
	@OneToOne(mappedBy = "products") //El name segun como se detallo en Suppliers
	private Suppliers suppliers;
		
	@ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE})
	@JoinTable(name = "producto_cliente",
	joinColumns = @JoinColumn(name="id_producto", nullable = false, unique = true,
	foreignKey = @ForeignKey(foreignKeyDefinition = "foreign key (id_producto) references products (id_producto)")),
	inverseJoinColumns = @JoinColumn(name="id_cliente", nullable = false, unique = true,
	foreignKey =  @ForeignKey(foreignKeyDefinition = "foreign key (id_cliente) references clients (id_cliente)")))	
	private List<Clients> clients=new ArrayList<>();

	
	public Integer getIdProducto() {
		return idProducto;
	}	
	public String getNombreProducto() {
		return nombreProducto;
	}

	public void setNombreProducto(String nombreProducto) {
		this.nombreProducto = nombreProducto;
	}

	public String getDescripcion() {
		return descripcion;
	}

	public void setDescripcion(String descripcion) {
		this.descripcion = descripcion;
	}

	public Double getPrecio() {
		return precio;
	}

	public void setPrecio(Double precio) {
		this.precio = precio;
	}

	public Integer getStock() {
		return stock;
	}

	public void setStock(Integer stock) {
		this.stock = stock;
	}

	public Suppliers getSuppliers() {
		return suppliers;
	}

	public void setSuppliers(Suppliers suppliers) {
		this.suppliers = suppliers;
	}

	public List<Clients> getClients() {
		return clients;
	}

	public void setClients(List<Clients> clients) {
		this.clients = clients;
	}

	public void setIdProducto(Integer idProducto) {
		this.idProducto = idProducto;
	}
	

	
}
