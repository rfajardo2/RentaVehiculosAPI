using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RentaVehiculosAPI.Data;
using RentaVehiculosAPI.Models;

namespace RentaVehiculosAPI.Controllers
{
    [Authorize(Roles = "administrador")]
    [Route("api/[controller]")]
    [ApiController]
    public class ClientesController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ClientesController(AppDbContext context)
        {
            _context = context;
        }

        // Obtener todos los clientes
        [HttpGet]
        public async Task<IActionResult> GetClientes()
        {
            var clientes = await _context.Clientes.ToListAsync();
            return Ok(clientes);
        }

        // Obtener un cliente por ID
        [HttpGet("{id}")]
        public async Task<IActionResult> GetCliente(int id)
        {
            var cliente = await _context.Clientes.FindAsync(id);
            if (cliente == null)
            {
                return NotFound(new { message = "Cliente no encontrado" });
            }

            return Ok(cliente);
        }

        // Crear un cliente
        [HttpPost]
        public async Task<IActionResult> CreateCliente([FromBody] Cliente cliente)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            _context.Clientes.Add(cliente);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetCliente), new { id = cliente.ID }, cliente);
        }

        // Actualizar un cliente
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateCliente(int id, [FromBody] Cliente cliente)
        {
            if (id != cliente.ID)
            {
                return BadRequest(new { message = "El ID del cliente no coincide" });
            }

            var clienteExistente = await _context.Clientes.FindAsync(id);
            if (clienteExistente == null)
            {
                return NotFound(new { message = "Cliente no encontrado" });
            }

            clienteExistente.Nombre = cliente.Nombre;
            clienteExistente.Direccion = cliente.Direccion;
            clienteExistente.Telefonos = cliente.Telefonos;
            clienteExistente.Licencia = cliente.Licencia;
            clienteExistente.Categoria = cliente.Categoria;
            clienteExistente.Observacion = cliente.Observacion;

            _context.Entry(clienteExistente).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            return Ok(clienteExistente);
        }

        // Eliminar un cliente
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteCliente(int id)
        {
            var cliente = await _context.Clientes.FindAsync(id);
            if (cliente == null)
            {
                return NotFound(new { message = "Cliente no encontrado" });
            }

            _context.Clientes.Remove(cliente);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Cliente eliminado exitosamente" });
        }
    }

}
